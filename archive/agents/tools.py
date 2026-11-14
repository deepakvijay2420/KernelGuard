import subprocess


class ToolManager:

    def read_document(self):

        print("[Tool] Reading document...")

        return "Research Paper Content"


    def summarize(self, text):

        print("[Tool] Summarizing...")

        with open("summary.txt", "w") as f:
            f.write("Summary Generated")

        print("[Tool] Summary Saved")


    def shell(self):

        print("[Tool] Opening Bash...")

        subprocess.run(["/bin/bash"])
