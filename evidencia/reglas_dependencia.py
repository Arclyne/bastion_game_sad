"""Comprueba las nueve reglas de dependencia de la sección 4.3 del SAD de Bastión.

Uso:
    python reglas_dependencia.py RUTA_DEL_REPOSITORIO_BASTION

Lee los .csproj y los archivos .cs del repositorio Arclyne/bastion (sin obj ni bin)
y dice, para cada regla, si pasa o falla y por qué. Sale con código 1 si alguna falla.
Solo usa la biblioteca estándar de Python.
"""

import re
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path

CLOCK_OR_RANDOM = re.compile(
    r"\bDateTime(?:Offset)?\.(?:Now|UtcNow|Today)\b|\bnew Random\b|\bRandom\.Shared\b"
    r"|\bRandomNumberGenerator\b|\bGuid\.NewGuid\b|\bTimeProvider\b"
)
CRYPTOGRAPHY = re.compile(r"\bSystem\.Security\.Cryptography\b")
DATABASE_ACCESS = re.compile(r"\bUseSqlServer\b|\bSqlConnection\b|\bMicrosoft\.Data\.SqlClient\b|\bBastionDbContext\b")
USING_DIRECTIVE = re.compile(r"^\s*using\s+(?:static\s+)?([A-Za-z_][\w.]*)\s*;", re.MULTILINE)
USING_ALIAS = re.compile(r"^\s*using\s+\w+\s*=\s*([A-Za-z_][\w.]*)", re.MULTILINE)


class Repository:
    def __init__(self, root):
        self.root = Path(root)

    def project_folder(self, name):
        for parent in ("src", "tests"):
            folder = self.root / parent / name
            if folder.is_dir():
                return folder
        raise FileNotFoundError(f"No existe el proyecto {name} en {self.root}")

    def project_file(self, name):
        return self.project_folder(name) / f"{name}.csproj"

    def project_references(self, name):
        tree = ElementTree.parse(self.project_file(name))
        references = {}
        for element in tree.iter("ProjectReference"):
            include = element.get("Include", "").replace("\\", "/")
            referenced = Path(include).stem
            private_assets = element.get("PrivateAssets") or element.findtext("PrivateAssets") or ""
            references[referenced] = private_assets.strip().lower()
        return references

    def package_references(self, name):
        tree = ElementTree.parse(self.project_file(name))
        return {element.get("Include") for element in tree.iter("PackageReference")}

    def source_files(self, name):
        folder = self.project_folder(name)
        files = []
        for path in sorted(folder.rglob("*.cs")):
            parts = set(path.relative_to(folder).parts)
            if "obj" in parts or "bin" in parts:
                continue
            files.append(path)
        return files

    def all_projects(self):
        names = []
        for parent in ("src", "tests"):
            folder = self.root / parent
            if folder.is_dir():
                names.extend(sorted(path.parent.name for path in folder.glob("*/*.csproj")))
        return names


def read_text(path):
    return path.read_text(encoding="utf-8-sig")


def using_namespaces(path):
    text = read_text(path)
    return set(USING_DIRECTIVE.findall(text)) | set(USING_ALIAS.findall(text))


def starts_with_any(namespace, prefixes):
    return any(namespace == prefix or namespace.startswith(prefix + ".") for prefix in prefixes)


def find_usings(repository, project, forbidden_prefixes):
    problems = []
    for path in repository.source_files(project):
        for namespace in sorted(using_namespaces(path)):
            if starts_with_any(namespace, forbidden_prefixes):
                problems.append(f"{path.name} usa {namespace}")
    return problems


def find_usings_outside(repository, project, allowed_prefixes):
    problems = []
    for path in repository.source_files(project):
        for namespace in sorted(using_namespaces(path)):
            if not starts_with_any(namespace, allowed_prefixes):
                problems.append(f"{path.name} usa {namespace}")
    return problems


def find_pattern(repository, project, pattern, description):
    problems = []
    for path in repository.source_files(project):
        match = pattern.search(read_text(path))
        if match:
            problems.append(f"{path.name} {description} ({match.group(0)})")
    return problems


def expect_references(repository, project, expected):
    actual = set(repository.project_references(project))
    if actual == set(expected):
        return []
    return [f"{project} referencia a {sorted(actual)}; se esperaba {sorted(expected)}"]


def expect_packages(repository, project, allowed):
    extra = repository.package_references(project) - set(allowed)
    return [f"{project} usa el paquete {package}" for package in sorted(extra)]


def rule_1(repository):
    project = "Bastion.Domain"
    problems = expect_references(repository, project, [])
    problems += expect_packages(repository, project, [])
    problems += find_usings_outside(repository, project, ["System", "Bastion.Domain"])
    problems += find_pattern(repository, project, CLOCK_OR_RANDOM, "lee el reloj o genera azar")
    return problems


def rule_2(repository):
    project = "Bastion.Contracts"
    problems = expect_references(repository, project, [])
    problems += expect_packages(repository, project, ["System.ServiceModel.Primitives"])
    problems += find_usings_outside(repository, project, ["System", "Bastion.Contracts"])
    allowed_users = {"Bastion.Server.Host", "Bastion.Client.Networking", "Bastion.Client.Tests"}
    for other in repository.all_projects():
        if project in repository.project_references(other) and other not in allowed_users:
            problems.append(f"{other} referencia a {project}")
    return problems


def rule_3(repository):
    project = "Bastion.Server.Application"
    problems = expect_references(repository, project, ["Bastion.Domain"])
    problems += expect_packages(repository, project, ["log4net"])
    problems += find_usings_outside(repository, project, ["System", "Bastion.Domain", "Bastion.Server.Application", "log4net"])
    problems += find_pattern(repository, project, CLOCK_OR_RANDOM, "lee el reloj o genera azar")
    problems += find_pattern(repository, project, CRYPTOGRAPHY, "usa criptografía")
    return problems


def rule_4(repository):
    project = "Bastion.Server.Adapters"
    problems = expect_references(repository, project, ["Bastion.Domain", "Bastion.Server.Application"])
    problems += find_usings(repository, project, ["Bastion.Contracts", "Bastion.Server.Host"])
    for core in ("Bastion.Domain", "Bastion.Server.Application"):
        problems += find_usings(repository, core, ["Bastion.Server.Adapters"])
    return problems


def rule_5(repository):
    project = "Bastion.Server.Host"
    problems = expect_references(
        repository, project, ["Bastion.Contracts", "Bastion.Server.Application", "Bastion.Server.Adapters"]
    )
    for path in repository.source_files(project):
        namespaces = using_namespaces(path)
        if path.name != "Program.cs" and any(starts_with_any(n, ["Bastion.Server.Adapters"]) for n in namespaces):
            problems.append(f"{path.name} usa Bastion.Server.Adapters fuera de Program.cs")
    problems += find_usings(repository, project, ["Microsoft.EntityFrameworkCore", "System.Data"])
    return problems


def rule_6(repository):
    project = "Bastion.Client"
    problems = expect_references(repository, project, ["Bastion.Client.Networking", "Bastion.Domain"])
    problems += find_usings(repository, project, ["Bastion.Contracts", "Bastion.Server", "System.ServiceModel"])
    return problems


def rule_7(repository):
    project = "Bastion.Client.Networking"
    references = repository.project_references(project)
    problems = expect_references(repository, project, ["Bastion.Contracts"])
    if references.get("Bastion.Contracts") not in (None, "all"):
        problems.append("Bastion.Contracts no es una referencia privada (PrivateAssets=\"all\")")
    problems += expect_packages(
        repository, project, ["System.ServiceModel.Primitives", "System.ServiceModel.NetTcp", "log4net"]
    )
    problems += find_usings(repository, project, ["Bastion.Domain", "Bastion.Server"])
    return problems


def rule_8(repository):
    problems = []
    for project in repository.all_projects():
        if project == "Bastion.Server.Adapters":
            continue
        problems += find_pattern(repository, project, DATABASE_ACCESS, "abre o nombra la conexión a la base")
    return problems


def rule_9(repository):
    problems = expect_references(repository, "Bastion.Domain.Tests", ["Bastion.Domain"])
    problems += expect_references(repository, "Bastion.Server.Application.Tests", ["Bastion.Server.Application"])
    for project in ("Bastion.Domain.Tests", "Bastion.Server.Application.Tests"):
        problems += find_usings(
            repository,
            project,
            ["Bastion.Server.Adapters", "Microsoft.EntityFrameworkCore", "System.Data", "System.ServiceModel"],
        )
        problems += find_pattern(repository, project, CLOCK_OR_RANDOM, "lee el reloj o genera azar")
    return problems


RULES = [
    (1, "C-05 no depende de nada", rule_1),
    (2, "C-02 no depende de ningún módulo de Bastión", rule_2),
    (3, "C-04 depende solo de C-05 y de log4net", rule_3),
    (4, "Los adaptadores conducidos dependen del núcleo, y nunca al revés", rule_4),
    (5, "C-03 es la raíz de composición y no usa tipos de acceso a datos", rule_5),
    (6, "C-01 depende solo de C-09 y C-05", rule_6),
    (7, "C-09 usa C-02 como referencia privada", rule_7),
    (8, "Solo C-06 se conecta a C-07", rule_8),
    (9, "Las pruebas del núcleo no usan C-06 ni C-07", rule_9),
]


def main(arguments):
    if len(arguments) != 2:
        sys.stderr.write(__doc__)
        return 2
    repository = Repository(arguments[1])
    failed_count = 0
    for number, title, check in RULES:
        problems = check(repository)
        verdict = "PASA" if not problems else f"FALLA ({len(problems)})"
        print(f"Regla {number} · {title}: {verdict}")
        for problem in problems:
            print(f"    - {problem}")
        if problems:
            failed_count += 1
    print(f"Resultado: {len(RULES) - failed_count} de {len(RULES)} reglas pasan.")
    return 1 if failed_count else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main(sys.argv))
