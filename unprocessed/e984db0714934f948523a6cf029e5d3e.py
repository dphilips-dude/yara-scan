import json
import os
from datetime import datetime
import shutil

class ReportNormalizer:
    def __init__(self, target_file=None, outfile=None):
        self.report_lines = []
        self.target_file = os.path.abspath(target_file) if target_file else "/tmp/reports/report.json"
        self.outfile = os.path.abspath(outfile) if outfile else "/tmp/reports/ingestable.json"

    def yara_string_normalize(self, yara_list):
        return [
            {**entry, "strings": ",".join([s['data'] for s in entry.get('strings', [])]) if entry.get('strings') else "No strings necessary for this rule"}
            for entry in yara_list
        ]

    def normalize(self):
        if not os.path.exists(self.target_file):
            return False
        
        with open(self.target_file, "r", encoding="utf-8") as report:
            for line in report:
                jline = json.loads(line)
                for filename, data in jline.items():
                    normalized_entry = {"filename": filename}
                    for key, value in data.items():
                        normalized_entry[key] = self.yara_string_normalize(value) if key == "Yara" else value
                    self.report_lines.append(normalized_entry)
        return self.report_lines
    
    def write_out(self):
        if os.path.exists(self.outfile) and os.path.getsize(self.outfile) > 50000 * 1024:
            shutil.move(self.outfile, f"{self.outfile}.{datetime.now().strftime('%Y%m%d_%H%M%S')}")

        with open(self.outfile, "a", encoding="utf-8") as f:
            for line in self.report_lines:
                json.dump(line, f)
                f.write("\n")


def main():
    rn = ReportNormalizer("/tmp/reports/test.json")
    if rn.normalize():
        rn.write_out()


if __name__ == "__main__":
    main()