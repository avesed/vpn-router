#!/usr/bin/env python3
"""
密钥管理模块 - 管理 SQLCipher 数据库加密密钥

功能：
1. 获取或创建部署密钥
2. 加密密钥用于备份导出
3. 解密密钥用于备份导入
4. 检测并迁移未加密数据库
"""

import base64
import logging
import os
import secrets
import shutil
import tempfile
from pathlib import Path
from typing import Optional

# Fernet 加密需要 cryptography 库
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# SQLCipher 需要 pysqlcipher3 库
try:
    from pysqlcipher3 import dbapi2 as sqlcipher
    HAS_SQLCIPHER = True
except ImportError:
    HAS_SQLCIPHER = False
    import sqlite3 as sqlcipher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class KeyManager:
    """数据库加密密钥管理器"""

    # 默认密钥文件路径
    DEFAULT_KEY_PATH = "/etc/sing-box/encryption.key"

    # PBKDF2 迭代次数
    PBKDF2_ITERATIONS = 100000

    @classmethod
    def get_key_path(cls) -> Path:
        """获取密钥文件路径（支持环境变量覆盖）"""
        return Path(os.environ.get("ENCRYPTION_KEY_PATH", cls.DEFAULT_KEY_PATH))

    @classmethod
    def get_or_create_key(cls) -> str:
        """获取或创建加密密钥

        Returns:
            64 字符的十六进制密钥字符串（32 字节）
        """
        key_path = cls.get_key_path()

        if key_path.exists():
            key = key_path.read_text().strip()
            if len(key) == 64:  # 有效的 hex 密钥
                return key
            logger.warning(f"Invalid key format in {key_path}, regenerating...")

        # 生成新密钥
        key = secrets.token_hex(32)  # 64 字符 hex = 32 字节

        # 确保目录存在
        key_path.parent.mkdir(parents=True, exist_ok=True)

        # 原子写入
        tmp_path = key_path.with_suffix(".tmp")
        tmp_path.write_text(key)
        os.chmod(tmp_path, 0o600)  # 仅 root 可读写
        tmp_path.rename(key_path)

        logger.info(f"Generated new encryption key: {key_path}")
        return key

    @classmethod
    def has_key(cls) -> bool:
        """检查密钥文件是否存在"""
        key_path = cls.get_key_path()
        if not key_path.exists():
            return False
        key = key_path.read_text().strip()
        return len(key) == 64

    @classmethod
    def _derive_key(cls, password: str, salt: bytes) -> bytes:
        """从密码派生加密密钥（PBKDF2-HMAC-SHA256）"""
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography library not available")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=cls.PBKDF2_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @classmethod
    def encrypt_key_for_export(cls, user_password: str) -> dict:
        """用用户密码加密部署密钥，用于备份导出

        Args:
            user_password: 用户提供的备份密码

        Returns:
            {
                "salt": base64 编码的 salt,
                "data": base64 编码的加密数据
            }
        """
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography library not available")

        key = cls.get_or_create_key()

        # 生成随机 salt
        salt = secrets.token_bytes(16)

        # 派生加密密钥
        derived_key = cls._derive_key(user_password, salt)

        # Fernet 加密
        f = Fernet(derived_key)
        encrypted = f.encrypt(key.encode())

        return {
            "salt": base64.b64encode(salt).decode(),
            "data": base64.b64encode(encrypted).decode(),
        }

    @classmethod
    def decrypt_key_from_import(cls, encrypted: dict, user_password: str) -> str:
        """从备份中解密部署密钥

        Args:
            encrypted: encrypt_key_for_export() 返回的加密数据
            user_password: 用户提供的备份密码

        Returns:
            解密后的密钥字符串

        Raises:
            ValueError: 密码错误或数据损坏
        """
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography library not available")

        try:
            salt = base64.b64decode(encrypted["salt"])
            data = base64.b64decode(encrypted["data"])

            # 派生加密密钥
            derived_key = cls._derive_key(user_password, salt)

            # Fernet 解密
            f = Fernet(derived_key)
            decrypted = f.decrypt(data)

            return decrypted.decode()
        except Exception as e:
            raise ValueError(f"Failed to decrypt key: {e}") from e

    @classmethod
    def save_key(cls, key: str) -> None:
        """保存密钥到文件

        Args:
            key: 64 字符的十六进制密钥
        """
        if len(key) != 64:
            raise ValueError("Key must be 64 hex characters (32 bytes)")

        key_path = cls.get_key_path()
        key_path.parent.mkdir(parents=True, exist_ok=True)

        # 原子写入
        tmp_path = key_path.with_suffix(".tmp")
        tmp_path.write_text(key)
        os.chmod(tmp_path, 0o600)
        tmp_path.rename(key_path)

        logger.info(f"Saved encryption key: {key_path}")

    @classmethod
    def is_database_encrypted(cls, db_path: str) -> bool:
        """检测数据库是否已加密

        Args:
            db_path: 数据库文件路径

        Returns:
            True 如果数据库已加密（SQLCipher），False 如果未加密
        """
        db_file = Path(db_path)
        if not db_file.exists():
            return False

        # 读取文件头
        with open(db_path, "rb") as f:
            header = f.read(16)

        # SQLite 未加密数据库以 "SQLite format 3\x00" 开头
        if header.startswith(b"SQLite format 3"):
            return False

        # SQLCipher 加密数据库有不同的头
        return True

    @classmethod
    def validate_key_for_database(cls, db_path: str, key: str) -> bool:
        """验证密钥是否能打开数据库

        Args:
            db_path: 数据库文件路径
            key: 加密密钥

        Returns:
            True 如果密钥正确
        """
        if not HAS_SQLCIPHER:
            return False

        try:
            conn = sqlcipher.connect(db_path)
            conn.execute(f"PRAGMA key = '{key}'")
            # 尝试读取表列表来验证密钥
            conn.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1")
            conn.close()
            return True
        except Exception:
            return False

    @classmethod
    def migrate_unencrypted_database(
        cls,
        db_path: str,
        key: Optional[str] = None
    ) -> bool:
        """迁移未加密数据库到加密数据库

        Args:
            db_path: 数据库文件路径
            key: 加密密钥（如果为 None，使用 get_or_create_key()）

        Returns:
            True 如果迁移成功
        """
        if not HAS_SQLCIPHER:
            logger.warning("SQLCipher not available, skipping migration")
            return False

        db_file = Path(db_path)
        if not db_file.exists():
            return False

        # 检查是否已加密
        if cls.is_database_encrypted(db_path):
            logger.info(f"Database already encrypted: {db_path}")
            return True

        if key is None:
            key = cls.get_or_create_key()

        logger.info(f"Migrating unencrypted database to encrypted: {db_path}")

        # 创建临时加密数据库
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # 使用标准 sqlite3 打开未加密数据库（重要！不能用 pysqlcipher3）
            import sqlite3
            src_conn = sqlite3.connect(db_path)

            # 创建加密数据库（使用 pysqlcipher3）
            # 使用 isolation_level="" 以便手动控制事务
            dst_conn = sqlcipher.connect(tmp_path, isolation_level="")
            dst_conn.execute(f"PRAGMA key = '{key}'")

            # 收集所有 SQL 语句，跳过事务控制语句
            sql_script = []
            for line in src_conn.iterdump():
                stripped = line.strip()
                # 跳过事务控制语句
                if stripped in ("BEGIN TRANSACTION;", "COMMIT;", "BEGIN;"):
                    continue
                sql_script.append(line)

            src_conn.close()

            # 使用 executescript 执行所有语句（它会自动处理事务）
            full_script = "\n".join(sql_script)
            dst_conn.executescript(full_script)
            dst_conn.close()

            # 备份原数据库
            backup_path = db_file.with_suffix(".db.unencrypted")
            shutil.copy2(db_path, backup_path)

            # 替换原数据库
            shutil.move(tmp_path, db_path)

            logger.info(f"Database migrated successfully. Backup: {backup_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to migrate database: {e}")
            import traceback
            logger.error(traceback.format_exc())
            # 清理临时文件
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            return False


def main():
    """命令行入口"""
    import argparse

    parser = argparse.ArgumentParser(description="Database encryption key manager")
    parser.add_argument("command", choices=["get", "create", "migrate", "check"])
    parser.add_argument("--db", help="Database path for migrate/check commands")

    args = parser.parse_args()

    if args.command == "get":
        # 获取或创建密钥并打印
        key = KeyManager.get_or_create_key()
        print(key)

    elif args.command == "create":
        # 强制创建新密钥
        key = secrets.token_hex(32)
        KeyManager.save_key(key)
        print(key)

    elif args.command == "migrate":
        if not args.db:
            print("Error: --db required for migrate command")
            return 1
        success = KeyManager.migrate_unencrypted_database(args.db)
        return 0 if success else 1

    elif args.command == "check":
        if not args.db:
            print("Error: --db required for check command")
            return 1
        encrypted = KeyManager.is_database_encrypted(args.db)
        print(f"Encrypted: {encrypted}")
        if encrypted and KeyManager.has_key():
            key = KeyManager.get_or_create_key()
            valid = KeyManager.validate_key_for_database(args.db, key)
            print(f"Key valid: {valid}")

    return 0


if __name__ == "__main__":
    exit(main())
