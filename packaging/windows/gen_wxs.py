"""Generate WiX source for the staged Windows payload."""

from __future__ import annotations

import argparse
import uuid
from pathlib import Path


def gid(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "phishguard:" + name)).upper()


def xml_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--runtime", required=True)
    args = parser.parse_args()

    root = Path(args.root)
    stage = Path(args.stage)
    runtime = Path(args.runtime)
    ico = root / "packaging/windows/phishguard.ico"

    buckets: dict[str, list[str]] = {"runtime": [], "runtime/phishguard": []}
    for path in sorted(runtime.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(runtime).as_posix()
        parent = "runtime" if "/" not in rel else "runtime/" + str(Path(rel).parent).replace("\\", "/")
        cid = "c" + gid(rel).replace("-", "")[:16]
        fid = "f" + gid("file:" + rel).replace("-", "")[:16]
        buckets.setdefault(parent, [])
        buckets[parent].append(
            "            <Component Id=\"{cid}\" Guid=\"{guid}\" Win64=\"yes\">\n"
            "              <File Id=\"{fid}\" Name=\"{name}\" Source=\"{source}\" KeyPath=\"yes\" />\n"
            "            </Component>".format(
                cid=cid,
                guid=gid("comp:" + rel),
                fid=fid,
                name=xml_escape(path.name),
                source=xml_escape(str(path)),
            )
        )

    refs: list[str] = []
    for items in buckets.values():
        for block in items:
            cid = block.split('Id="')[1].split('"')[0]
            refs.append(f'      <ComponentRef Id="{cid}" />')

    runtime_inner = "\n".join(buckets.get("runtime", []))
    pkg_inner = "\n".join(buckets.get("runtime/phishguard", []))
    exe = stage / "PhishGuard.exe"
    wxs = f"""<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="PhishGuard" Language="1033" Version="1.0.0"
           Manufacturer="PhishGuard" UpgradeCode="99230E05-AB4F-46B6-BD21-67BFB013A54C">
    <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine"
             Description="Local phishing URL detector for Windows" />
    <MajorUpgrade DowngradeErrorMessage="A newer version of PhishGuard is already installed." />
    <MediaTemplate EmbedCab="yes" />
    <Icon Id="AppIcon" SourceFile="{xml_escape(str(ico))}" />
    <Property Id="ARPPRODUCTICON" Value="AppIcon" />
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFiles64Folder">
        <Directory Id="INSTALLDIR" Name="PhishGuard">
          <Component Id="MainExe" Guid="AC503AB5-F175-4118-A527-5487F548CA72" Win64="yes">
            <File Id="PhishGuardExe" Name="PhishGuard.exe" Source="{xml_escape(str(exe))}" KeyPath="yes">
              <Shortcut Id="StartMenuShortcut" Directory="ApplicationProgramsFolder"
                        Name="PhishGuard" WorkingDirectory="INSTALLDIR" Icon="AppIcon" Advertise="no" />
              <Shortcut Id="DesktopShortcut" Directory="DesktopFolder"
                        Name="PhishGuard" WorkingDirectory="INSTALLDIR" Icon="AppIcon" Advertise="no" />
            </File>
          </Component>
          <Directory Id="RuntimeDir" Name="runtime">
{runtime_inner}
            <Directory Id="PhishPkgDir" Name="phishguard">
{pkg_inner}
            </Directory>
          </Directory>
        </Directory>
      </Directory>
      <Directory Id="ProgramMenuFolder">
        <Directory Id="ApplicationProgramsFolder" Name="PhishGuard">
          <Component Id="StartMenuDir" Guid="B3C1E4D2-8A11-4F20-9C44-1D2E3F4A5B6C" Win64="yes">
            <RemoveFolder Id="ApplicationProgramsFolder" On="uninstall" />
            <RegistryValue Root="HKCU" Key="Software\\PhishGuard" Name="StartMenu" Type="integer" Value="1" KeyPath="yes" />
          </Component>
        </Directory>
      </Directory>
      <Directory Id="DesktopFolder" Name="Desktop" />
    </Directory>
    <Feature Id="Main" Title="PhishGuard" Level="1">
      <ComponentRef Id="MainExe" />
      <ComponentRef Id="StartMenuDir" />
{chr(10).join(refs)}
    </Feature>
  </Product>
</Wix>
"""
    out = stage / "product.wxs"
    out.write_text(wxs, encoding="utf-8")
    print("wrote", out, "components", sum(len(v) for v in buckets.values()))


if __name__ == "__main__":
    main()
