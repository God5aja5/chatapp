#!/usr/bin/env python3
import os
import shutil
import sys

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "chat.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
STICKER_FOLDER = os.path.join(BASE_DIR, "stickers")
SETTINGS_PATH = os.path.join(BASE_DIR, "admin_settings.json")


def remove_file(path):
    if os.path.exists(path):
        os.remove(path)
        return True
    return False


def clear_folder(folder):
    if not os.path.isdir(folder):
        return 0
    removed = 0
    for name in os.listdir(folder):
        if name.startswith("."):
            continue
        path = os.path.join(folder, name)
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            removed += 1
        except Exception:
            print(f"Failed to remove {path}")
    return removed


def main():
    keep_uploads = "--keep-uploads" in sys.argv
    keep_settings = "--keep-settings" in sys.argv
    keep_stickers = "--keep-stickers" in sys.argv
    force = "--force" in sys.argv

    if not force:
        print("This will reset the database and optionally clear uploads/settings/stickers.")
        print("Make sure the server is stopped before continuing.")
        answer = input("Type YES to continue: ").strip()
        if answer != "YES":
            print("Canceled.")
            return 1

    removed_db = remove_file(DB_PATH)
    removed_uploads = 0 if keep_uploads else clear_folder(UPLOAD_FOLDER)
    removed_settings = False if keep_settings else remove_file(SETTINGS_PATH)
    removed_stickers = 0 if keep_stickers else clear_folder(STICKER_FOLDER)

    print("Reset complete:")
    print(f"- chat.db removed: {removed_db}")
    print(f"- uploads cleared: {removed_uploads} file(s)")
    print(f"- admin_settings.json removed: {removed_settings}")
    print(f"- stickers cleared: {removed_stickers} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
