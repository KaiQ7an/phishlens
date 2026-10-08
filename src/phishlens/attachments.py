"""Attachment risk by name and type. Contents are never opened."""

from __future__ import annotations

from .message import Attachment

EXECUTABLE = frozenset({"exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe",
                        "wsf", "ps1", "hta", "msi", "jar", "lnk", "cpl", "reg"})
MACRO_DOCUMENTS = frozenset({"docm", "xlsm", "pptm", "dotm", "xlam"})
DISK_IMAGES = frozenset({"iso", "img", "vhd", "vhdx"})
ARCHIVES = frozenset({"zip", "rar", "7z", "gz", "tar", "cab"})
HTML = frozenset({"html", "htm", "shtml", "svg"})
DECOY = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "csv"})


def extensions(filename: str) -> list[str]:
    return [part.lower() for part in filename.strip().split(".")[1:]]


def classify(attachment: Attachment) -> list[tuple[str, str, str]]:
    """Return (severity, code, explanation) tuples for one attachment."""
    exts = extensions(attachment.filename)
    if not exts:
        return []
    last = exts[-1]
    issues: list[tuple[str, str, str]] = []
    if len(exts) >= 2 and exts[-2] in DECOY and last in EXECUTABLE:
        issues.append(("high", "attachment.double_extension",
                       f"'{attachment.filename}' looks like a .{exts[-2]} but is a .{last} program"))
    elif last in EXECUTABLE:
        issues.append(("high", "attachment.executable", f"'{attachment.filename}' is a program or script"))
    if last in MACRO_DOCUMENTS:
        issues.append(("medium", "attachment.macro", f"'{attachment.filename}' is an Office file that can run macros"))
    if last in HTML:
        issues.append(("high", "attachment.html",
                       f"'{attachment.filename}' is a web page; attached pages are a common way to host fake login forms"))
    if last in DISK_IMAGES:
        issues.append(("medium", "attachment.disk_image", f"'{attachment.filename}' is a disk image, often used to smuggle programs"))
    elif last in ARCHIVES:
        issues.append(("low", "attachment.archive", f"'{attachment.filename}' is an archive whose contents cannot be checked here"))
    return issues


# Phrases that hand over an archive password in the message itself. Encrypted
# archives cannot be scanned in transit, which is why attackers use them.
PASSWORD_PHRASES = ("password is", "password:", "passcode is", "密码是", "密码：", "密码:", "解压密码")


def encrypted_archive(attachment: Attachment, text: str) -> tuple[str, str, str] | None:
    """Flag an archive sent alongside its own password. Only the text is read."""
    exts = extensions(attachment.filename)
    lowered = text.lower()
    if exts and exts[-1] in ARCHIVES and any(phrase in lowered for phrase in PASSWORD_PHRASES):
        return ("high", "attachment.encrypted_archive",
                f"'{attachment.filename}' arrives with its password in the message, which keeps "
                "scanners from looking inside")
    return None
