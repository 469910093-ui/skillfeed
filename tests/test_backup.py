"""用户库备份：一致副本 + 轮转，不碰投稿门禁。"""

import tempfile
import unittest
from pathlib import Path

from server import backup, db


class TestSqliteBackup(unittest.TestCase):
    def test_backup_copies_users_and_prunes(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "server.db"
            dest = Path(tmp) / "backups"
            db.init_db(src)
            with db.db_session(src) as conn:
                db.upsert_user(conn, github_id=99, login="keep-me")
            first = backup.backup_sqlite(src, dest, keep=2)
            self.assertTrue(first.is_file())
            with db.db_session(first) as conn:
                row = conn.execute("SELECT login FROM users WHERE github_id=99").fetchone()
                self.assertEqual(row["login"], "keep-me")
            backup.backup_sqlite(src, dest, keep=2)
            backup.backup_sqlite(src, dest, keep=2)
            self.assertEqual(len(list(dest.glob("server-*.db"))), 2)
            status = backup.backup_status(dest)
            self.assertEqual(status["count"], 2)
            self.assertTrue(status["latest"].startswith("server-"))
