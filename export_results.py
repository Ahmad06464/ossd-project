import json

from openpyxl import Workbook

from scan_import_export import MARKER, build_scan_payload, embed_json_block

TOOL_WIDTH = 18
VALUE_WIDTH = 42
STATUS_WIDTH = 8
IP_WIDTH = 16
NOTE_WIDTH = 20
SCREENSHOT_WIDTH = 30


def _build_payload(results, meta=None):
    meta = meta or {}
    resume_fields = {
        key: meta[key]
        for key in (
            "scan_status", "completed_tools", "resume_from_tool",
            "tool_statuses", "runner_state", "session_dir",
        )
        if key in meta and meta[key]
    }
    return build_scan_payload(
        target=meta.get("target", ""),
        results=results,
        profile=meta.get("profile", ""),
        scan_completed_at=meta.get("scan_completed_at", ""),
        targets=meta.get("targets"),
        exported_at=meta.get("exported_at"),
        resume_fields=resume_fields or None,
    )


def export_txt(path, results, meta=None):
    payload = _build_payload(results, meta)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(f"# {MARKER}\n")
        handle.write(f"# target: {payload.get('target', '')}\n")
        handle.write(f"# scan_completed_at: {payload.get('scan_completed_at', '')}\n")
        handle.write(f"# exported_at: {payload.get('exported_at', '')}\n")
        handle.write(f"# profile: {payload.get('profile', '')}\n")
        handle.write(f"# results: {len(results)}\n")
        handle.write("# ---\n")
        handle.write(
            f"{'Type':<8} {'Tool(s)':<{TOOL_WIDTH}} {'Value':<{VALUE_WIDTH}} "
            f"{'Status':<{STATUS_WIDTH}} {'IP/Related':<{IP_WIDTH}} "
            f"{'Note':<{NOTE_WIDTH}}\n"
        )
        handle.write("-" * 130 + "\n")

        for row in results:
            related = row.get("ip") if row.get("type") == "host" else row.get("related", row.get("ip", ""))
            handle.write(
                f"{row.get('type', ''):<8} {row.get('tools', ''):<{TOOL_WIDTH}} "
                f"{row.get('value', ''):<{VALUE_WIDTH}} "
                f"{row.get('status', ''):<{STATUS_WIDTH}} {related:<{IP_WIDTH}} "
                f"{row.get('note', ''):<{NOTE_WIDTH}}\n"
            )

        handle.write("\n# --- Re-import: File → Import scan export...\n")
        handle.write(embed_json_block(payload))
        handle.write("\n")


def export_excel(path, results, meta=None):
    payload = _build_payload(results, meta)
    workbook = Workbook()

    meta_sheet = workbook.active
    meta_sheet.title = "ScanMeta"
    meta_sheet["A1"] = json.dumps(payload)
    meta_sheet["A2"] = "target"
    meta_sheet["B2"] = payload.get("target", "")
    meta_sheet["A3"] = "scan_completed_at"
    meta_sheet["B3"] = payload.get("scan_completed_at", "")
    meta_sheet["A4"] = "exported_at"
    meta_sheet["B4"] = payload.get("exported_at", "")
    meta_sheet["A5"] = "profile"
    meta_sheet["B5"] = payload.get("profile", "")
    meta_sheet["A6"] = "results_count"
    meta_sheet["B6"] = len(results)

    sheet = workbook.create_sheet("Results")
    sheet.append(["Type", "Tool(s)", "Value", "Status", "IP/Related", "Note", "Screenshot"])

    for row in results:
        related = row.get("ip") if row.get("type") == "host" else row.get("related", row.get("ip", ""))
        sheet.append([
            row.get("type", ""),
            row.get("tools", ""),
            row.get("value", ""),
            row.get("status", ""),
            related,
            row.get("note", ""),
            row.get("screenshot", ""),
        ])

    for column, width in zip("ABCDEFG", (10, 22, 50, 10, 18, 24, 40)):
        sheet.column_dimensions[column].width = width

    workbook.save(path)
