#!/usr/bin/env python3
"""
统一日志配置模块

通过环境变量控制全局日志级别：
- LOG_LEVEL: Python 日志级别 (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- RUST_LOG: Rust 组件日志级别 (已在 entrypoint.sh 中处理)

使用方式：
    from log_config import setup_logging, get_logger
    
    # 在模块入口处调用一次
    setup_logging()
    
    # 获取 logger
    logger = get_logger(__name__)
    logger.info("Hello")
"""

import logging
import os
import sys
from typing import Optional

# 默认日志级别
DEFAULT_LOG_LEVEL = "INFO"

# 日志格式
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_FORMAT_DETAILED = "%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# 全局配置标志，防止重复配置
_logging_configured = False


def get_log_level() -> int:
    """从环境变量获取日志级别
    
    支持的环境变量（按优先级）：
    1. LOG_LEVEL - 显式设置的日志级别
    2. DEBUG - 如果设置为 "1" 或 "true"，则使用 DEBUG 级别
    
    Returns:
        logging 模块的日志级别常量
    """
    # 检查 LOG_LEVEL 环境变量
    level_str = os.environ.get("LOG_LEVEL", "").upper().strip()
    
    # 如果没有设置 LOG_LEVEL，检查 DEBUG 标志
    if not level_str:
        debug_flag = os.environ.get("DEBUG", "").lower().strip()
        if debug_flag in ("1", "true", "yes", "on"):
            level_str = "DEBUG"
        else:
            level_str = DEFAULT_LOG_LEVEL
    
    # 映射字符串到日志级别
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "WARN": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
        "FATAL": logging.CRITICAL,
    }
    
    return level_map.get(level_str, logging.INFO)


def setup_logging(
    name: Optional[str] = None,
    level: Optional[int] = None,
    detailed: bool = False,
    force: bool = False
) -> logging.Logger:
    """配置全局日志
    
    Args:
        name: Logger 名称，None 表示 root logger
        level: 日志级别，None 表示从环境变量获取
        detailed: 是否使用详细格式（包含文件名和行号）
        force: 是否强制重新配置（即使已经配置过）
    
    Returns:
        配置好的 Logger 实例
    """
    global _logging_configured
    
    if _logging_configured and not force:
        return logging.getLogger(name)
    
    # 获取日志级别
    if level is None:
        level = get_log_level()
    
    # 选择日志格式
    log_format = LOG_FORMAT_DETAILED if detailed else LOG_FORMAT
    
    # 配置 root logger
    logging.basicConfig(
        level=level,
        format=log_format,
        datefmt=DATE_FORMAT,
        stream=sys.stderr,
        force=force or not _logging_configured
    )
    
    # 设置第三方库的日志级别（减少噪音）
    for lib_logger in ["urllib3", "requests", "aiohttp", "httpx"]:
        logging.getLogger(lib_logger).setLevel(max(level, logging.WARNING))
    
    _logging_configured = True
    
    logger = logging.getLogger(name)
    logger.debug(f"Logging configured: level={logging.getLevelName(level)}")
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """获取命名 logger
    
    如果全局日志尚未配置，会自动调用 setup_logging()
    
    Args:
        name: Logger 名称，通常使用 __name__
    
    Returns:
        Logger 实例
    """
    if not _logging_configured:
        setup_logging()
    
    return logging.getLogger(name)


def set_log_level(level: int) -> None:
    """动态设置日志级别
    
    Args:
        level: logging 模块的日志级别常量
    """
    logging.getLogger().setLevel(level)
    logging.info(f"Log level changed to: {logging.getLevelName(level)}")


# 提供便捷的日志级别常量
DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL


if __name__ == "__main__":
    # 测试日志配置
    setup_logging(detailed=True)
    logger = get_logger(__name__)
    
    logger.debug("This is a DEBUG message")
    logger.info("This is an INFO message")
    logger.warning("This is a WARNING message")
    logger.error("This is an ERROR message")
    
    print(f"\nCurrent log level: {logging.getLevelName(get_log_level())}")
    print(f"Set LOG_LEVEL environment variable to change (DEBUG, INFO, WARNING, ERROR)")
