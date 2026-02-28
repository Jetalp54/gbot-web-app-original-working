import sys
import os
import shutil
import json
import re
import time
import logging
import smtplib
import threading
import random
import string
import pandas as pd
from faker import Faker
import pyotp
import undetected_chromedriver as uc
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException, NoSuchElementException, WebDriverException
)
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QSplitter, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QComboBox, QTextEdit, QFileDialog, QListWidget, QListWidgetItem,
    QMessageBox, QDialog, QScrollArea, QGroupBox, QTabWidget, QAction,
    QInputDialog, QPlainTextEdit, QGridLayout
)
from PyQt5.QtCore import Qt, QMetaObject, Q_ARG, pyqtSlot, QTimer
from PyQt5.QtGui import QColor

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import BatchHttpRequest
import google.auth.transport.requests
import paramiko

# -------------------------
# Constants & Logging
# -------------------------
SCOPES = [
    'https://www.googleapis.com/auth/admin.directory.user',
    'https://www.googleapis.com/auth/admin.directory.domain'
]

LOCAL_TOKEN_FILE = 'tokens.json' # Used for temporary write before upload
LOCAL_ACCOUNTS_FILE = 'accounts.json' # Used for temporary write before upload
# ACCOUNTS_LOCK_FILE removed
DESKTOP_PATH = os.path.join(os.path.expanduser('~'), 'Desktop')
BACKUP_DIR = os.path.join(DESKTOP_PATH, 'backup')
BULK_CHANGE_DIR = os.path.join(DESKTOP_PATH, 'Maintenance', 'BulkDomainChange')


# --- SFTP/SSH server info ---
SERVER_ADDRESS = '46.224.9.127'
SERVER_PORT = 22
USERNAME = 'root'
PASSWORD = 'JnsQ3G98JU027QP'
REMOTE_DIR = '/home/Google_Api/'
REMOTE_ALT_DIR = '/home/brightmindscampus/' # Define secondary directory

# --- Remote File Paths --- #
REMOTE_ACCOUNTS_FILENAME = 'accounts.json'
REMOTE_TOKENS_FILENAME = 'tokens.json'

REMOTE_ACCOUNTS_PATH_PRIMARY = os.path.join(REMOTE_DIR, REMOTE_ACCOUNTS_FILENAME).replace('\\', '/')
REMOTE_ACCOUNTS_PATH_SECONDARY = os.path.join(REMOTE_ALT_DIR, REMOTE_ACCOUNTS_FILENAME).replace('\\', '/')

REMOTE_TOKENS_PATH_PRIMARY = os.path.join(REMOTE_DIR, REMOTE_TOKENS_FILENAME).replace('\\', '/')
REMOTE_TOKENS_PATH_SECONDARY = os.path.join(REMOTE_ALT_DIR, REMOTE_TOKENS_FILENAME).replace('\\', '/')

logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Global state for tokens mtime
_last_tokens_mtime = None # For tokens.json

# Global state for accounts.json (NEW or MODIFIED)
ACCOUNTS = {}
_last_accounts_mtime = None
_last_loaded_accounts_path = None


import html

# -----------------------------------------------------------------------------
# Replace your existing token‐loading helpers with this:
# -----------------------------------------------------------------------------
def load_tokens_with_mtime(sftp):
    """
    SFTP‐decorated loader: returns (tokens_dict, mtime) of the first
    existing server-side tokens.json, or ({}, None) if none found.
    """
    paths = [REMOTE_TOKENS_PATH_PRIMARY, REMOTE_TOKENS_PATH_SECONDARY]
    for p in paths:
        try:
            # read + parse
            with sftp.open(p, 'r') as f:
                tokens = json.load(f)
            # fetch modification time
            mtime = sftp.stat(p).st_mtime
            return tokens, mtime
        except (FileNotFoundError, json.JSONDecodeError, IOError):
            continue
    return {}, None

# -------------------------
# Style Sheets
# -------------------------
modern_stylesheet_dark = """
    QWidget {
       background-color: #1e1e2f;
       color: #e0e0e0;
       font-family: 'Segoe UI', sans-serif;
       font-size: 10pt;
    }
    QPushButton {
       background-color: #3a3f58;
       border: none;
       border-radius: 8px;
       padding: 8px 16px;
       min-height: 20px; /* Ensure buttons have minimum height */
    }
    QPushButton:hover {
       background-color: #4a4f68;
    }
    QPushButton:pressed {
       background-color: #2a2f48;
    }
    QLineEdit, QTextEdit, QComboBox, QListWidget, QPlainTextEdit {
       background-color: #2b2b3d;
       border: 1px solid #3a3f58;
       border-radius: 6px;
       padding: 4px;
       color: #e0e0e0; /* Ensure text color is light */
    }
    QComboBox::drop-down {
       subcontrol-origin: padding;
       subcontrol-position: top right;
       width: 24px;
       border-left: 1px solid #3a3f58;
    }
    /* Style the arrow */
    QComboBox::down-arrow {
       /* Consider using an image for a custom arrow if needed */
       /* image: url(path/to/your/arrow-down-dark.png); */
       width: 12px;
       height: 12px;
    }
    QGroupBox {
       border: 1px solid #3a3f58;
       border-radius: 8px;
       margin-top: 10px;
       padding-top: 15px; /* Add padding to prevent title overlap */
    }
    QGroupBox::title {
       subcontrol-origin: margin;
       subcontrol-position: top left;
       padding: 0 8px;
       background-color: #1e1e2f; /* Match background */
       color: #a0a0e0; /* Lighter title color */
       left: 10px; /* Adjust position */
    }
    QTabWidget::pane {
       border: 1px solid #3a3f58;
       border-radius: 8px;
       margin: 0px;
       padding: 5px; /* Add padding inside tab pane */
    }
    QTabBar::tab {
       background: #3a3f58;
       border: 1px solid #3a3f58;
       border-bottom: none; /* Remove bottom border for non-selected */
       border-top-left-radius: 8px;
       border-top-right-radius: 8px;
       padding: 8px 16px;
       margin-right: 2px; /* Add space between tabs */
       color: #c0c0c0; /* Slightly dimmer text for non-selected tabs */
    }
    QTabBar::tab:selected {
       background: #4a4f68;
       border-bottom-color: #4a4f68; /* Match background */
       color: #ffffff; /* Bright text for selected tab */
    }
    QTabBar::tab:hover {
       background: #4a4f68;
       color: #ffffff;
    }
    QScrollArea {
        border: none; /* Remove border from scroll area itself */
    }
    /* Style scrollbars for dark theme */
    QScrollBar:vertical {
        border: 1px solid #3a3f58;
        background: #2b2b3d;
        width: 12px;
        margin: 0px 0px 0px 0px;
    }
    QScrollBar::handle:vertical {
        background: #4a4f68;
        min-height: 20px;
        border-radius: 6px;
    }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        background: none;
        height: 0px;
        subcontrol-position: top;
        subcontrol-origin: margin;
    }
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
        background: none;
    }
    QScrollBar:horizontal {
        border: 1px solid #3a3f58;
        background: #2b2b3d;
        height: 12px;
        margin: 0px 0px 0px 0px;
    }
    QScrollBar::handle:horizontal {
        background: #4a4f68;
        min-width: 20px;
        border-radius: 6px;
    }
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
        background: none;
        width: 0px;
        subcontrol-position: left;
        subcontrol-origin: margin;
    }
    QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
        background: none;
    }
    QLabel {
        color: #e0e0e0; /* Ensure labels are visible */
    }
    QMessageBox {
        background-color: #2b2b3d; /* Dark background for message boxes */
    }
    QMessageBox QLabel {
        color: #e0e0e0; /* Light text */
    }
    QMessageBox QPushButton { /* Style buttons inside QMessageBox */
        background-color: #3a3f58;
        color: #e0e0e0;
        border: none;
        border-radius: 6px;
        padding: 6px 12px;
        min-width: 70px;
    }
    QMessageBox QPushButton:hover {
        background-color: #4a4f68;
    }
    QMessageBox QPushButton:pressed {
        background-color: #2a2f48;
    }
"""

modern_stylesheet_light = """
    QWidget {
       background-color: #f0f0f0;
       color: #333333;
       font-family: 'Segoe UI', sans-serif;
       font-size: 10pt;
    }
    QPushButton {
       background-color: #e0e0e0;
       border: 1px solid #cccccc; /* Add subtle border */
       border-radius: 8px;
       padding: 8px 16px;
       min-height: 20px;
    }
    QPushButton:hover {
       background-color: #d8d8d8; /* Slightly darker hover */
    }
    QPushButton:pressed {
       background-color: #cccccc; /* Darker pressed */
    }
    QLineEdit, QTextEdit, QComboBox, QListWidget, QPlainTextEdit {
       background-color: #ffffff;
       border: 1px solid #cccccc;
       border-radius: 6px;
       padding: 4px;
       color: #333333; /* Ensure text color is dark */
    }
    QComboBox::drop-down {
       subcontrol-origin: padding;
       subcontrol-position: top right;
       width: 24px;
       border-left: 1px solid #cccccc;
       border-radius: 0 6px 6px 0; /* Match corner radius */
    }
    /* Style the arrow for light theme */
    QComboBox::down-arrow {
       /* image: url(path/to/your/arrow-down-light.png); */
       width: 12px;
       height: 12px;
    }
    QGroupBox {
       border: 1px solid #cccccc;
       border-radius: 8px;
       margin-top: 10px;
       padding-top: 15px;
    }
    QGroupBox::title {
       subcontrol-origin: margin;
       subcontrol-position: top left;
       padding: 0 8px;
       background-color: #f0f0f0; /* Match background */
       color: #555555; /* Darker title color */
       left: 10px;
    }
    QTabWidget::pane {
       border: 1px solid #cccccc;
       border-radius: 8px;
       margin: 0px;
       padding: 5px;
       background-color: #f0f0f0; /* Ensure pane background matches */
    }
    QTabBar::tab {
       background: #e0e0e0;
       border: 1px solid #cccccc;
       border-bottom: none;
       border-top-left-radius: 8px;
       border-top-right-radius: 8px;
       padding: 8px 16px;
       margin-right: 2px;
       color: #777777; /* Dimmer text for non-selected tabs */
    }
    QTabBar::tab:selected {
       background: #f0f0f0; /* Match window background */
       border-bottom-color: #f0f0f0; /* Make it look connected */
       color: #333333; /* Standard text color */
    }
    QTabBar::tab:hover {
       background: #eaeaea;
       color: #333333;
    }
    QScrollArea {
        border: none;
    }
    /* Style scrollbars for light theme */
    QScrollBar:vertical {
        border: 1px solid #cccccc;
        background: #f0f0f0;
        width: 12px;
        margin: 0px 0px 0px 0px;
    }
    QScrollBar::handle:vertical {
        background: #d0d0d0;
        min-height: 20px;
        border-radius: 6px;
    }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        background: none;
        height: 0px;
    }
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
        background: none;
    }
    QScrollBar:horizontal {
        border: 1px solid #cccccc;
        background: #f0f0f0;
        height: 12px;
        margin: 0px 0px 0px 0px;
    }
    QScrollBar::handle:horizontal {
        background: #d0d0d0;
        min-width: 20px;
        border-radius: 6px;
    }
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
        background: none;
        width: 0px;
    }
    QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
        background: none;
    }
    QLabel {
        color: #333333; /* Ensure labels are visible */
    }
    QMessageBox {
        background-color: #f0f0f0; /* Light background for message boxes */
    }
    QMessageBox QLabel {
        color: #333333; /* Dark text */
    }
    QMessageBox QPushButton {
        background-color: #e0e0e0;
        color: #333333;
        border: 1px solid #cccccc;
        border-radius: 6px;
        padding: 6px 12px;
        min-width: 70px;
    }
    QMessageBox QPushButton:hover {
        background-color: #d8d8d8;
    }
    QMessageBox QPushButton:pressed {
        background-color: #cccccc;
    }
"""


# -------------------------
# Helper: Try loading JSON for an account
# -------------------------
def try_load_json_for_account(email):
    """
    Constructs the remote path: <email>/<email>.json.
    Attempts to load from /home/Google_Api/<email>/<email>.json.
    If not found, tries /home/brightmindscampus/<email>/<email>.json.
    Returns the local filename if successful; otherwise raises an exception.
    """
    local_filename = f"{email}.json"
    remote_subpath = f"{email}/{email}.json"
    # First attempt: /home/Google_Api
    try:
        with paramiko.Transport((SERVER_ADDRESS, SERVER_PORT)) as transport:
            transport.connect(username=USERNAME, password=PASSWORD)
            with paramiko.SFTPClient.from_transport(transport) as sftp:
                sftp.get(os.path.join(REMOTE_DIR, remote_subpath).replace('\\', '/'), local_filename) # Ensure forward slashes
        logging.info(f"Loaded JSON from /home/Google_Api/{remote_subpath}")
        return local_filename
    except Exception as e1:
        logging.warning(f"Not found in /home/Google_Api/{remote_subpath}: {e1}") # Log full path
    # Second attempt: /home/brightmindscampus
    alt_dir = '/home/brightmindscampus/'
    try:
        with paramiko.Transport((SERVER_ADDRESS, SERVER_PORT)) as transport:
            transport.connect(username=USERNAME, password=PASSWORD)
            with paramiko.SFTPClient.from_transport(transport) as sftp:
                sftp.get(os.path.join(alt_dir, remote_subpath).replace('\\', '/'), local_filename) # Ensure forward slashes
        logging.info(f"Loaded JSON from /home/brightmindscampus/{remote_subpath}")
        return local_filename
    except Exception as e2:
        logging.error(f"Not found in /home/brightmindscampus/{remote_subpath}: {e2}") # Log full path
        # Raise the *second* error if both fail, indicating the final attempt failed
        raise FileNotFoundError(f"Could not find JSON file for {email} in primary or secondary locations.") from e2


# -------------------------
# Additional Utility Functions (REVISED)
# -------------------------
def ensure_dir(dir_path):
    # ... (implementation unchanged) ...
    if not os.path.exists(dir_path):
        try:
            os.makedirs(dir_path)
            logging.info(f"Created directory: {dir_path}")
        except OSError as e:
            logging.error(f"Failed to create directory {dir_path}: {e}")

def ensure_backup_dir():
    ensure_dir(BACKUP_DIR)

def ensure_bulk_change_dir():
    ensure_dir(BULK_CHANGE_DIR)

# -------------------------
# Utility Functions (REVISED)
# -------------------------
def backup_local_file(file_path):
    """Backs up file, logs errors, returns True/False. Avoids early QMessageBox."""
    if not os.path.exists(file_path):
        logging.warning(f"Attempted to back up non-existent file: {file_path}")
        return False
    ensure_backup_dir()
    try:
        file_name = os.path.basename(file_path)
        backup_path = os.path.join(BACKUP_DIR, f"{file_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        shutil.copy2(file_path, backup_path)
        logging.info(f"Backed up {file_path} to {backup_path}")
        return True
    except Exception as e:
         log_msg = f"Failed to back up {file_path}: {e}"
         logging.error(log_msg)
         app_instance = QApplication.instance()
         # Check if main_window_ref exists on app_instance (set in MainWindow.__init__)
         if app_instance and hasattr(app_instance, 'main_window_ref') and app_instance.main_window_ref:
             QMetaObject.invokeMethod(
                 app_instance.main_window_ref, # Use the stored reference
                 "_show_backup_warning_message",
                 Qt.QueuedConnection,
                 Q_ARG(str, f"Could not back up {os.path.basename(file_path)}. See log.")
             )
         return False

def save_to_server(local_path, remote_target_path):
    """Saves a local file to a specific remote path. Raises ConnectionError on failure."""
    try:
        with paramiko.Transport((SERVER_ADDRESS, SERVER_PORT)) as transport:
            transport.connect(username=USERNAME, password=PASSWORD)
            with paramiko.SFTPClient.from_transport(transport) as sftp:
                sftp.put(local_path, remote_target_path)
        logging.info(f"Saved {local_path} to server at {remote_target_path}")
    except Exception as e:
        logging.error(f"Failed to save file '{os.path.basename(local_path)}' to server path '{remote_target_path}': {e}")
        raise ConnectionError(f"Failed to save {os.path.basename(local_path)} to server: {e}") from e

# -------------------------
# Global ACCOUNTS dictionary and initial load (REVISED)
# -------------------------
def initialize_accounts():
    """Loads accounts on startup, preferring server. Avoids early QMessageBox."""
    global ACCOUNTS, _last_accounts_mtime, _last_loaded_accounts_path # Ensure all three are global
    try:
        logging.info("Attempting initial load of accounts from server...")
        # Correctly unpack all three values returned by the function
        ACCOUNTS, mtime, path = load_accounts_from_server_with_mtime()
        _last_accounts_mtime = mtime # Assign to the correct global
        _last_loaded_accounts_path = path # Assign to the correct global

        if ACCOUNTS or _last_accounts_mtime is not None: # Check if server load was successful (even if empty file)
            logging.info(f"Initial load from server successful (mtime: {_last_accounts_mtime}, path: {_last_loaded_accounts_path}). Loaded {len(ACCOUNTS)} accounts.")
        else:
            # This block executes if load_accounts_from_server_with_mtime returned ({}, None, None)
            # indicating a complete failure to load from the server.
            logging.warning("Initial load: Could not load accounts from server or file was empty/corrupt on all paths. Checking local.")
            if os.path.exists(LOCAL_ACCOUNTS_FILE):
                 logging.warning(f"Attempting fallback to local file: {LOCAL_ACCOUNTS_FILE}")
                 try:
                      with open(LOCAL_ACCOUNTS_FILE, 'r') as f:
                           ACCOUNTS = json.load(f)
                           _last_accounts_mtime = None # Indicate local load, mtime unknown
                           _last_loaded_accounts_path = None # Path is local
                           logging.info(f"Successfully loaded {len(ACCOUNTS)} accounts from local fallback.")
                 except (json.JSONDecodeError, IOError) as json_err:
                      logging.error(f"Error decoding/reading local fallback {LOCAL_ACCOUNTS_FILE}: {json_err}. Initializing empty.")
                      backup_local_file(LOCAL_ACCOUNTS_FILE) # Backup corrupt local file
                      ACCOUNTS = {}
                      _last_accounts_mtime = None
                      _last_loaded_accounts_path = None
            else:
                 logging.warning(f"Local file {LOCAL_ACCOUNTS_FILE} also not found. Initializing empty accounts.")
                 ACCOUNTS = {}
                 _last_accounts_mtime = None
                 _last_loaded_accounts_path = None

    except ConnectionError as e_conn: # Catches SFTP connection errors from the decorator
        logging.error(f"Initial account load failed due to SFTP connection error: {e_conn}. Checking local fallback.")
        if os.path.exists(LOCAL_ACCOUNTS_FILE):
             logging.warning(f"Attempting fallback to local file due to connection error: {LOCAL_ACCOUNTS_FILE}")
             try:
                  with open(LOCAL_ACCOUNTS_FILE, 'r') as f:
                       ACCOUNTS = json.load(f)
                  _last_accounts_mtime = None
                  _last_loaded_accounts_path = None
                  logging.info(f"Successfully loaded {len(ACCOUNTS)} accounts from local fallback.")
             except (json.JSONDecodeError, IOError) as e_local_conn:
                  logging.error(f"Error reading/decoding local fallback {LOCAL_ACCOUNTS_FILE} after connection error: {e_local_conn}. Initializing empty.")
                  backup_local_file(LOCAL_ACCOUNTS_FILE)
                  ACCOUNTS = {}
                  _last_accounts_mtime = None
                  _last_loaded_accounts_path = None
        else:
             logging.warning(f"Local file {LOCAL_ACCOUNTS_FILE} also not found after connection error. Initializing empty accounts.")
             ACCOUNTS = {}
             _last_accounts_mtime = None
             _last_loaded_accounts_path = None
    except Exception as e: # Catch-all for truly unexpected issues during init
        logging.critical(f"An unexpected critical error occurred during initial accounts loading: {e}", exc_info=True)
        ACCOUNTS = {} # Ensure it's a dict even on fatal error
        _last_accounts_mtime = None
        _last_loaded_accounts_path = None
        # The MainWindow __init__ will show a warning later if ACCOUNTS is empty


def _sftp_operation(func):
    """Decorator to handle SFTP connection and closing."""
    def wrapper(*args, **kwargs):
        sftp = None
        transport = None
        try:
            transport = paramiko.Transport((SERVER_ADDRESS, SERVER_PORT))
            transport.connect(username=USERNAME, password=PASSWORD)
            sftp = paramiko.SFTPClient.from_transport(transport)
            logging.debug(f"SFTP connection established for {func.__name__}")
            return func(sftp, *args, **kwargs)
        except paramiko.AuthenticationException as auth_err:
            logging.error(f"SFTP Authentication failed: {auth_err}")
            raise ConnectionError("SFTP Authentication failed.") from auth_err
        except paramiko.SSHException as ssh_ex:
            logging.error(f"SFTP SSH connection error: {ssh_ex}")
            raise ConnectionError(f"SFTP SSH connection error: {ssh_ex}") from ssh_ex
        except Exception as e:
            logging.error(f"SFTP operation error in {func.__name__}: {e}", exc_info=True)
            raise ConnectionError(f"SFTP operation failed: {e}") from e
        finally:
            if sftp:
                sftp.close()
                logging.debug("SFTP client closed.")
            if transport and transport.is_active():
                transport.close()
                logging.debug("SFTP transport closed.")
    return wrapper

@_sftp_operation
def load_tokens_with_mtime(sftp):
    """
    SFTP‐decorated loader: returns (tokens_dict, mtime) of the first
    existing server-side tokens.json, or ({}, None) if none found.
    """
    paths = [REMOTE_TOKENS_PATH_PRIMARY, REMOTE_TOKENS_PATH_SECONDARY]
    for p in paths:
        try:
            with sftp.open(p, 'r') as f:
                tokens = json.load(f)
            mtime = sftp.stat(p).st_mtime
            logging.info(f"Loaded tokens from {p} (mtime: {mtime})")
            return tokens, mtime
        except (FileNotFoundError, json.JSONDecodeError, IOError) as e:
            logging.warning(f"Failed to load tokens from {p}: {e}. Trying next.")
            continue
    logging.warning("Tokens file not found on server or failed to load from all paths.")
    return {}, None

@_sftp_operation
def load_accounts_from_server_with_mtime(sftp):
    """
    Attempts to load accounts.json from primary, then secondary server location.
    Returns (loaded_accounts_dict, mtime, loaded_from_path).
    Returns ({}, None, None) if not found or on error that prevents loading.
    """
    remote_paths_to_try = [REMOTE_ACCOUNTS_PATH_PRIMARY, REMOTE_ACCOUNTS_PATH_SECONDARY]
    for remote_path in remote_paths_to_try:
        try:
            with sftp.open(remote_path, 'r') as f:
                content = f.read()
                if not content.strip(): # Check for empty content
                    logging.warning(f"Accounts file at {remote_path} is empty. Treating as empty dict.")
                    loaded_accounts = {}
                else:
                    loaded_accounts = json.loads(content)

            file_stat = sftp.stat(remote_path)
            mtime = file_stat.st_mtime
            logging.info(f"Successfully loaded accounts from {remote_path} (mtime: {mtime})")
            return loaded_accounts, mtime, remote_path
        except FileNotFoundError:
            logging.warning(f"Accounts file not found at {remote_path}. Trying next location.")
        except json.JSONDecodeError as json_err:
            logging.error(f"Failed to decode JSON from {remote_path}: {json_err}. Trying next location.")
        except Exception as e:
            logging.error(f"Error reading or stating file at {remote_path}: {e}. Trying next location.")

    logging.warning("Could not load accounts from any server location or all attempts failed.")
    return {}, None, None


@_sftp_operation
def check_server_mtime(sftp, remote_path):
    """Gets the modification time of a remote file. Returns mtime or None."""
    try:
        file_stat = sftp.stat(remote_path)
        return file_stat.st_mtime
    except FileNotFoundError:
        logging.warning(f"check_server_mtime: File not found at {remote_path}")
        return None
    except Exception as e:
        logging.error(f"Error stating file at {remote_path}: {e}")
        return None

# -------------------------
# Helper: Try loading JSON for an account (for Auto-Add) (REVISED)
# -------------------------
def try_load_json_for_account(email):
    """
    Constructs the remote path: <email>/<email>.json.
    Attempts to load from /home/Google_Api/<email>/<email>.json.
    If not found, tries /home/brightmindscampus/<email>/<email>.json.
    Returns the local filename if successful; otherwise raises an exception.
    """
    local_filename = f"{email}_credential_temp.json" # Make temp name more specific
    remote_subpath = f"{email}/{email}.json"
    # First attempt: /home/Google_Api
    try:
        with paramiko.Transport((SERVER_ADDRESS, SERVER_PORT)) as transport:
            transport.connect(username=USERNAME, password=PASSWORD)
            with paramiko.SFTPClient.from_transport(transport) as sftp:
                sftp.get(os.path.join(REMOTE_DIR, remote_subpath).replace('\\', '/'), local_filename)
        logging.info(f"Downloaded JSON from {os.path.join(REMOTE_DIR, remote_subpath)} to {local_filename}")
        return local_filename
    except Exception as e1:
        logging.warning(f"Not found or error in {os.path.join(REMOTE_DIR, remote_subpath)}: {e1}")
    # Second attempt: /home/brightmindscampus
    try:
        with paramiko.Transport((SERVER_ADDRESS, SERVER_PORT)) as transport:
            transport.connect(username=USERNAME, password=PASSWORD)
            with paramiko.SFTPClient.from_transport(transport) as sftp:
                sftp.get(os.path.join(REMOTE_ALT_DIR, remote_subpath).replace('\\', '/'), local_filename)
        logging.info(f"Downloaded JSON from {os.path.join(REMOTE_ALT_DIR, remote_subpath)} to {local_filename}")
        return local_filename
    except Exception as e2:
        logging.error(f"Not found or error in {os.path.join(REMOTE_ALT_DIR, remote_subpath)}: {e2}")
        raise FileNotFoundError(f"Could not find or download JSON file for {email} from primary or secondary locations.") from e2



# -------------------------
# Global ACCOUNTS dictionary and initial load DEFINITIONS
# -------------------------

# def initialize_accounts(): # This definition is already above and is fine.
#     """Loads accounts on startup, preferring server. Avoids early QMessageBox."""
#     global ACCOUNTS, _last_loaded_mtime # Corrected global name to _last_accounts_mtime
#     # ... rest of the function ...

# NO OTHER ACCOUNT LOADING BLOCKS HERE



# -----------------------------------------------------------------------------
# In GoogleAPI.authenticate(), replace the token_lookup_key logic with:
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# GoogleAPI Class (Authentication and Token Saving REVISED)
# -----------------------------------------------------------------------------
class GoogleAPI:
    def __init__(self):
        # self.tokens_file = LOCAL_TOKEN_FILE # Still used for temporary local write
        self.service = None
        self.current_account_name = None
        # self.tokens (dictionary holding all tokens) is removed.
        # Authentication will rely on fresh loads via load_tokens_with_mtime.

    def authenticate(self, account_name_from_ui, client_id, client_secret, project_name=""):
        global _last_tokens_mtime
        logging.info(f"--- Starting authentication attempt for UI key: {account_name_from_ui} ---")

        current_server_tokens = {}
        try:
            fresh_tokens, mtime = load_tokens_with_mtime()
            if mtime is not None and mtime != _last_tokens_mtime:
                logging.info(f"tokens.json changed on server (mtime={mtime}, last known={_last_tokens_mtime}), reloading.")
                _last_tokens_mtime = mtime
                current_server_tokens = fresh_tokens
            elif mtime is None and _last_tokens_mtime is not None:
                logging.warning("tokens.json might have become inaccessible on server. Using empty tokens.")
                _last_tokens_mtime = None; current_server_tokens = {}
            elif mtime is not None:
                 _last_tokens_mtime = mtime; current_server_tokens = fresh_tokens
            else: current_server_tokens = {}
        except ConnectionError as e_sftp:
            logging.error(f"SFTP Error: Could not fetch tokens.json: {e_sftp}. Authentication may fail or require browser flow.")
            QMessageBox.warning(None, "SFTP Warning", f"Could not fetch tokens.json from server:\n{e_sftp}\nProceeding with new authentication if needed.")
        except Exception as e:
            logging.error(f"Unexpected error loading tokens: {e}", exc_info=True)
            QMessageBox.critical(None, "Token Load Error", f"Unexpected error fetching tokens.json:\n{e}")
            return False

        token_lookup_key = account_name_from_ui
        creds, needs_browser_auth = None, False

        if token_lookup_key in current_server_tokens:
            data = current_server_tokens[token_lookup_key]
            required = ['token', 'refresh_token', 'token_uri', 'client_id', 'client_secret', 'scopes']
            if all(k in data for k in required):
                try:
                    creds = Credentials.from_authorized_user_info(data, SCOPES)
                    if creds.valid: logging.info("Loaded valid credentials from server token cache.")
                    elif creds.expired and creds.refresh_token:
                        logging.info("Token expired, attempting refresh..."); creds.refresh(google.auth.transport.requests.Request())
                        current_server_tokens[token_lookup_key] = json.loads(creds.to_json())
                        self.save_tokens(current_server_tokens)
                        logging.info("Refreshed and saved token.")
                    else: logging.warning("Token invalid, cannot refresh. Need browser auth."); needs_browser_auth = True
                except Exception as e_refresh:
                    logging.error(f"Error processing/refreshing stored token for {token_lookup_key}: {e_refresh}. Requiring browser auth.")
                    needs_browser_auth = True
            else: logging.warning(f"Token data for {token_lookup_key} incomplete. Need browser auth."); needs_browser_auth = True
        else: logging.info(f"No token for {token_lookup_key} in cache. Need browser auth."); needs_browser_auth = True

        if needs_browser_auth:
            logging.info(f"Initiating browser authentication flow for {account_name_from_ui}.")
            try:
                flow_config = {"installed": {"client_id": client_id, "project_id": project_name or "gbot-project", "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token", "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs", "client_secret": client_secret, "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]}}
                flow = InstalledAppFlow.from_client_config(flow_config, SCOPES)
                creds = flow.run_local_server(port=0)
                try:
                    reloaded_tokens_before_save, _ = load_tokens_with_mtime()
                    reloaded_tokens_before_save[token_lookup_key] = json.loads(creds.to_json())
                    self.save_tokens(reloaded_tokens_before_save)
                except ConnectionError as e_sftp_reload:
                    logging.error(f"SFTP error reloading tokens before save: {e_sftp_reload}. Saving current view.")
                    current_server_tokens[token_lookup_key] = json.loads(creds.to_json())
                    self.save_tokens(current_server_tokens)
                logging.info(f"Browser auth successful for {account_name_from_ui}, token saved.")
            except Exception as e_flow:
                logging.error(f"Browser auth flow failed for {account_name_from_ui}: {e_flow}", exc_info=True)
                QMessageBox.critical(None, "Browser Auth Failed", f"Could not complete browser auth for {account_name_from_ui}: {e_flow}")
                return False

        if creds and creds.valid:
            self.service = build('admin', 'directory_v1', credentials=creds)
            self.current_account_name = account_name_from_ui
            logging.info(f"Authentication successful for {account_name_from_ui}. Service built.")
            return True
        else:
            logging.error(f"Authentication ultimately failed for {account_name_from_ui}.")
            if not needs_browser_auth: QMessageBox.critical(None, "Auth Failed", f"Could not authenticate {account_name_from_ui}.")
            return False

    def save_tokens(self, tokens_to_save):
        global _last_tokens_mtime
        if not isinstance(tokens_to_save, dict): logging.error("save_tokens: invalid data type."); return
        try:
            backup_local_file(LOCAL_TOKEN_FILE)
            with open(LOCAL_TOKEN_FILE, 'w') as f: json.dump(tokens_to_save, f, indent=4)
            logging.info(f"Saved {len(tokens_to_save)} token entries locally to {LOCAL_TOKEN_FILE}")
            try:
                save_to_server(LOCAL_TOKEN_FILE, REMOTE_TOKENS_PATH_PRIMARY)
                logging.info(f"Uploaded tokens to primary: {REMOTE_TOKENS_PATH_PRIMARY}")
                new_mtime = check_server_mtime(REMOTE_TOKENS_PATH_PRIMARY)
                if new_mtime: _last_tokens_mtime = new_mtime
                return
            except ConnectionError as e_primary:
                logging.error(f"Failed save tokens to primary {REMOTE_TOKENS_PATH_PRIMARY}: {e_primary}. Trying secondary...")
                try:
                    save_to_server(LOCAL_TOKEN_FILE, REMOTE_TOKENS_PATH_SECONDARY)
                    logging.info(f"Uploaded tokens to secondary: {REMOTE_TOKENS_PATH_SECONDARY}")
                    new_mtime = check_server_mtime(REMOTE_TOKENS_PATH_SECONDARY)
                    if new_mtime: _last_tokens_mtime = new_mtime
                    return
                except ConnectionError as e_secondary:
                    logging.error(f"Failed save tokens to secondary {REMOTE_TOKENS_PATH_SECONDARY}: {e_secondary}")
                    raise ConnectionError("Failed to save tokens to both primary and secondary server locations.") from e_secondary
        except Exception as e:
            logging.error(f"Failed to save tokens: {e}", exc_info=True)
            QMessageBox.critical(None, "Token Save Error", f"Failed to save tokens:\n{e}")





    def create_user(self, user_info):
        if not self.service:
             QMessageBox.critical(None, "Error", "Not authenticated. Please authenticate first.")
             return None
        try:
            result = self.service.users().insert(body=user_info).execute()
            email = result.get('primaryEmail')
            logging.info(f"User inserted: {email}")

            # Short delay to allow propagation, then check/unsuspend if needed
            time.sleep(2) # Keep the delay, sometimes needed
            try:
                # Check if user is suspended (sometimes they are created suspended)
                user_check = self.service.users().get(userKey=email, projection='full').execute() # Use projection='full'
                if user_check.get('suspended'):
                    logging.warning(f"User {email} was created in suspended state. Attempting to unsuspend.")
                    self.service.users().update(userKey=email, body={'suspended': False}).execute()
                    logging.info(f"User unsuspended immediately after creation: {email}")
                else:
                     logging.info(f"User {email} created in active state.")

            except HttpError as e_get:
                # Handle 404 specifically - might still be propagating
                if e_get.resp.status == 404:
                    logging.warning(f"User {email} created but not immediately retrievable (404). Assuming active state.")
                # Handle 403 - Permissions issue?
                elif e_get.resp.status == 403:
                     logging.error(f"Permission denied when trying to check/unsuspend user {email}: {e_get}. User might remain suspended if created so.")
                     QMessageBox.warning(None, "Permission Error", f"Could not check/unsuspend {email} after creation due to permissions.")
                else:
                    logging.error(f"Error retrieving/unsuspending user {email} after creation: {e_get}")
            except Exception as e_inner:
                 logging.error(f"Unexpected error during post-creation check for {email}: {e_inner}")


            return email
        except HttpError as error:
            error_content = error.content.decode('utf-8')
            logging.error(f"User creation failed for {user_info.get('primaryEmail')}: {error} - {error_content}")
            # Provide more specific feedback if possible
            error_details = f"Error: {error.resp.status} {error.resp.reason}"
            try:
                error_json = json.loads(error_content)
                if 'error' in error_json and 'message' in error_json['error']:
                    error_details += f"\nDetails: {error_json['error']['message']}"
            except json.JSONDecodeError:
                error_details += f"\nRaw Response: {error_content}"

            QMessageBox.critical(None, "User Creation Failed", f"Failed to create user {user_info.get('primaryEmail')}.\n{error_details}")
            return None
        except Exception as e: # Catch other potential errors (e.g., network issues)
             logging.error(f"Unexpected error during user creation for {user_info.get('primaryEmail')}: {e}")
             QMessageBox.critical(None, "User Creation Error", f"An unexpected error occurred while creating user {user_info.get('primaryEmail')}: {e}")
             return None


    def delete_user(self, user_email):
        if not self.service:
             QMessageBox.critical(None, "Error", "Not authenticated. Please authenticate first.")
             return False
        try:
            self.service.users().delete(userKey=user_email).execute()
            logging.info(f"Successfully deleted user: {user_email}")
            return True
        except HttpError as error:
            error_content = error.content.decode('utf-8')
            # Check for 404 Not Found - User might have been deleted already
            if error.resp.status == 404:
                logging.warning(f"Attempted to delete non-existent user: {user_email}. Treating as 'success' for batch operations.")
                # Show a less critical message if needed, or just log
                # QMessageBox.warning(None, "User Not Found", f"User {user_email} does not exist or was already deleted.")
                return True # Return True because the desired state (user gone) is achieved
            # Log other errors
            logging.error(f"User deletion failed for {user_email}: {error} - {error_content}")
            error_details = f"Error: {error.resp.status} {error.resp.reason}"
            try:
                error_json = json.loads(error_content)
                if 'error' in error_json and 'message' in error_json['error']:
                    error_details += f"\nDetails: {error_json['error']['message']}"
            except json.JSONDecodeError:
                 error_details += f"\nRaw Response: {error_content}"
            # Show critical message for failures other than 404
            QMessageBox.critical(None, "User Deletion Failed", f"Failed to delete user {user_email}.\n{error_details}")
            return False
        except Exception as e:
             logging.error(f"Unexpected error during user deletion for {user_email}: {e}")
             QMessageBox.critical(None, "User Deletion Error", f"An unexpected error occurred deleting {user_email}: {e}")
             return False


    def update_user(self, user_email, user_info):
        if not self.service:
             QMessageBox.critical(None, "Error", "Not authenticated. Please authenticate first.")
             return False
        try:
            result = self.service.users().update(userKey=user_email, body=user_info).execute()
            logging.info(f"Successfully updated user: {user_email} with info: {user_info}. Result: {result.get('primaryEmail')}")
            return True
        except HttpError as error:
            error_content = error.content.decode('utf-8')
            logging.error(f"User update failed for {user_email} with data {user_info}: {error} - {error_content}")
            error_details = f"Error: {error.resp.status} {error.resp.reason}"
            try:
                error_json = json.loads(error_content)
                if 'error' in error_json and 'message' in error_json['error']:
                    error_details += f"\nDetails: {error_json['error']['message']}"
            except json.JSONDecodeError:
                 error_details += f"\nRaw Response: {error_content}"

            # Specific check for domain change failure due to alias conflict
            if 'primaryEmail' in user_info and error.resp.status == 400 and 'Entity already exists' in error_content:
                 error_details += "\nPossible cause: The new email address might already exist as an alias for another user."

            QMessageBox.critical(None, "User Update Failed", f"Failed to update user {user_email}.\n{error_details}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error during user update for {user_email}: {e}")
            QMessageBox.critical(None, "User Update Error", f"An unexpected error occurred updating {user_email}: {e}")
            return False


    def list_suspended_users(self):
        if not self.service:
             QMessageBox.critical(None, "Error", "Not authenticated. Please authenticate first.")
             return []
        try:
            suspended_users = []
            page_token = None
            while True:
                 results = self.service.users().list(
                     customer='my_customer',
                     query='isSuspended=true',
                     maxResults=500, # Max allowed per page
                     projection='basic', # Only need basic info (like email)
                     orderBy='email', # Optional: order results
                     pageToken=page_token
                 ).execute()

                 users = results.get('users', [])
                 suspended_users.extend(users)

                 page_token = results.get('nextPageToken')
                 if not page_token:
                     break # Exit loop if no more pages
            logging.info(f"Retrieved {len(suspended_users)} suspended users.")
            return suspended_users
        except HttpError as error:
            logging.error(f"Failed to list suspended users: {error}")
            QMessageBox.critical(None, "API Error", f"Failed to list suspended users: {error}")
            return []
        except Exception as e:
             logging.error(f"Unexpected error listing suspended users: {e}")
             QMessageBox.critical(None, "Error", f"An unexpected error occurred while listing suspended users: {e}")
             return []


    def unsuspend_user(self, user_email):
        if not self.service:
             QMessageBox.critical(None, "Error", "Not authenticated. Please authenticate first.")
             return False
        try:
            self.service.users().update(userKey=user_email, body={'suspended': False}).execute()
            logging.info(f"User unsuspended: {user_email}")
            return True
        except HttpError as error:
             error_content = error.content.decode('utf-8') # Get more details
             # Check for specific abuse suspension error
             if error.resp.status == 412 and "Cannot restore a user suspended for abuse" in error_content:
                 abuse_msg = f"Cannot unsuspend user {user_email} because they were suspended for abuse. Manual intervention via Admin Console is required."
                 logging.error(abuse_msg)
                 QMessageBox.critical(None, "Unsuspend Error", abuse_msg)
             elif error.resp.status == 403:
                 perm_msg = f"Permission denied trying to unsuspend {user_email}. Check API scope permissions."
                 logging.error(f"{perm_msg} Error: {error}")
                 QMessageBox.critical(None, "Permission Error", perm_msg)
             else:
                 logging.error(f"Failed to unsuspend user {user_email}: {error} - {error_content}")
                 QMessageBox.critical(None, "Unsuspend Error", f"Failed to unsuspend user {user_email}: {error}")
             return False
        except Exception as e:
             logging.error(f"Unexpected error unsuspending user {user_email}: {e}")
             QMessageBox.critical(None, "Error", f"An unexpected error occurred while unsuspending {user_email}: {e}")
             return False


    def get_subdomains(self):
        if not self.service:
            QMessageBox.critical(None, "Error", "Not authenticated. Please authenticate first.")
            return [] # Return an empty list if not authenticated

        try:
            # Step 1: Fetch all domains from API
            domain_results = self.service.domains().list(customer='my_customer').execute()
            api_domain_list_from_google = domain_results.get('domains', [])

            if not api_domain_list_from_google:
                logging.warning("No domains (verified or unverified) returned by API for this account.")
                return []

            # Step 2: Create a flat list of initial_info_dicts for all *verified* domains,
            # preserving their API response order. Also create a map for quick info access.
            flat_verified_domains_ordered_info = [] # Will store info_dicts
            domain_info_map = {} # Maps domain_name to its info_dict for easy updates

            for domain_api_info in api_domain_list_from_google:
                if domain_api_info.get('verified'):
                    domain_name = domain_api_info.get('domainName')
                    if domain_name:
                        initial_info = {
                            'domain_name': domain_name,
                            'used_active': False,
                            'count_total': 0,
                            'count_active': 0
                        }
                        flat_verified_domains_ordered_info.append(initial_info) # Store the dict directly
                        domain_info_map[domain_name] = initial_info # Map the same dict instance

            if not flat_verified_domains_ordered_info:
                logging.warning("No *verified* domains found for this account after filtering.")
                return []

            # Log the order of domains as they are initially processed from the API response
            logging.info(f"Verified domains (in API processing order): {[d['domain_name'] for d in flat_verified_domains_ordered_info]}")


            # Step 3: Populate user counts into domain_info_map (which updates the dicts in flat_verified_domains_ordered_info)
            page_token = None
            user_count_processed = 0
            logging.info("Starting user list to analyze domain usage...")
            while True:
                result = self.service.users().list(
                    customer='my_customer', maxResults=500, projection='basic',
                    fields='nextPageToken,users(primaryEmail,suspended)', pageToken=page_token
                ).execute()
                users_in_page = result.get('users', [])
                user_count_processed += len(users_in_page)

                for user in users_in_page:
                    email = user.get('primaryEmail', '')
                    if '@' in email:
                        user_domain_part = email.split('@')[1]
                        if user_domain_part in domain_info_map:
                            info_dict_to_update = domain_info_map[user_domain_part]
                            info_dict_to_update['count_total'] += 1
                            if not user.get('suspended', False):
                                info_dict_to_update['used_active'] = True
                                info_dict_to_update['count_active'] += 1
                
                page_token = result.get('nextPageToken')
                if not page_token:
                    logging.info(f"Finished analyzing domain usage for {user_count_processed} total users.")
                    break
            
            # Step 4: Grouping Phase - Identify parents and their subdomains
            # The final structure: List[Tuple[parent_info_dict, List[sub_info_dict]]]
            # Each parent_info_dict and sub_info_dict will be the *updated* dicts from domain_info_map.
            
            grouped_result_list = []
            all_verified_names_set = set(domain_info_map.keys()) # For quick lookups
            
            processed_as_parent_or_subdomain = set() # Track all domains that have been placed

            # Iterate through verified domains in their original API order to establish parent groups
            for current_domain_info in flat_verified_domains_ordered_info:
                current_domain_name = current_domain_info['domain_name']

                if current_domain_name in processed_as_parent_or_subdomain:
                    continue # Already handled as part of another group or as a standalone parent

                # A domain is a "parent for grouping" if it's not a subdomain of *any other verified* domain
                is_sub_of_another_verified = False
                for other_domain_name_in_set in all_verified_names_set:
                    if current_domain_name != other_domain_name_in_set and \
                       current_domain_name.endswith("." + other_domain_name_in_set):
                        is_sub_of_another_verified = True
                        break
                
                if not is_sub_of_another_verified:
                    # This is a parent domain (or a standalone domain to be treated as a parent)
                    parent_info_dict_with_counts = current_domain_info # This info_dict already has user counts
                    subdomains_for_this_parent = [] # List of sub_info_dicts
                    
                    processed_as_parent_or_subdomain.add(current_domain_name)

                    # Now find its subdomains, also in their original API order
                    for potential_sub_info in flat_verified_domains_ordered_info:
                        potential_sub_name = potential_sub_info['domain_name']
                        if potential_sub_name != current_domain_name and \
                           potential_sub_name.endswith("." + current_domain_name):
                            # This is a subdomain of the current_domain_name
                            if potential_sub_name not in processed_as_parent_or_subdomain:
                                sub_info_dict_with_counts = potential_sub_info # Already has counts
                                subdomains_for_this_parent.append(sub_info_dict_with_counts)
                                processed_as_parent_or_subdomain.add(potential_sub_name)
                    
                    # **CRITICAL FIX HERE**: Always append a tuple (parent_info, list_of_subs)
                    # Even if list_of_subs is empty.
                    grouped_result_list.append( (parent_info_dict_with_counts, subdomains_for_this_parent) )

            return grouped_result_list

        except HttpError as error:
            logging.error(f"API error retrieving domains or users: {error}")
            QMessageBox.critical(None, "API Error", f"Failed to retrieve domain/user information: {error}")
            return []
        except Exception as e:
            logging.error(f"Unexpected error retrieving subdomains/user counts: {e}", exc_info=True)
            QMessageBox.critical(None, "Error", f"An unexpected error occurred: {e}")
            return []

    def clear_subdomain_display(self):
        # This method seems tied to the UI, perhaps move it to MainWindow?
        # For now, just pass if it's only called from MainWindow.
        pass


# -------------------------
# Dialog for Manual Account Addition
# -------------------------
class AddAccountDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add New Account Manually")
        self.setModal(True)
        self.layout = QVBoxLayout(self)
        self.setMinimumWidth(400) # Give it a bit more space

        # Use QGroupBox for better visual separation
        details_group = QGroupBox("Account Credentials")
        details_layout = QVBoxLayout(details_group)

        self.account_name_label = QLabel("Account Name (e.g., your_admin@domain.com):")
        details_layout.addWidget(self.account_name_label)
        self.account_name_entry = QLineEdit()
        self.account_name_entry.setPlaceholderText("Enter the Google Workspace admin email")
        details_layout.addWidget(self.account_name_entry)

        self.client_id_label = QLabel("Client ID:")
        details_layout.addWidget(self.client_id_label)
        self.client_id_entry = QLineEdit()
        self.client_id_entry.setPlaceholderText("Enter the Client ID from Google Cloud Console")
        details_layout.addWidget(self.client_id_entry)

        self.client_secret_label = QLabel("Client Secret:")
        details_layout.addWidget(self.client_secret_label)
        self.client_secret_entry = QLineEdit()
        self.client_secret_entry.setPlaceholderText("Enter the Client Secret")
        self.client_secret_entry.setEchoMode(QLineEdit.Password) # Hide secret
        details_layout.addWidget(self.client_secret_entry)

        self.layout.addWidget(details_group)

        # Buttons layout
        button_layout = QHBoxLayout()
        self.add_account_btn = QPushButton("✅ Add Account")
        self.add_account_btn.clicked.connect(self.accept)
        self.cancel_btn = QPushButton("❌ Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addStretch() # Push buttons to the right
        button_layout.addWidget(self.cancel_btn)
        button_layout.addWidget(self.add_account_btn)

        self.layout.addLayout(button_layout)
        self.setLayout(self.layout) # Set the main layout

    def get_account_details(self):
        # Strip whitespace from inputs
        return (self.account_name_entry.text().strip(),
                    self.client_id_entry.text().strip(),
                    self.client_secret_entry.text().strip())

# -------------------------
# Dialog for Auto Adding Accounts (Multi-line Emails)
# -------------------------
class AddFromJSONDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Auto Add Accounts from JSON Files")
        self.setModal(True)
        self.setMinimumWidth(450) # Wider dialog
        layout = QVBoxLayout(self)

        info_label = QLabel(
             "Enter one or more Google Workspace admin email addresses below (one per line).\n"
             "The application will search for corresponding <email>.json credential files\n"
             "on the SFTP server in '/home/Google_Api/' and '/home/brightmindscampus/'."
        )
        info_label.setWordWrap(True) # Allow text wrapping
        layout.addWidget(info_label)

        self.emails_text = QPlainTextEdit()
        self.emails_text.setPlaceholderText("admin1@example.com\nadmin2@anotherexample.org\n...")
        self.emails_text.setMinimumHeight(150) # Make text area taller
        layout.addWidget(self.emails_text)

        btn_layout = QHBoxLayout()
        self.ok_button = QPushButton("🔍 Find & Add Accounts")
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("❌ Cancel")
        self.cancel_button.clicked.connect(self.reject)
        btn_layout.addStretch()
        btn_layout.addWidget(self.cancel_button)
        btn_layout.addWidget(self.ok_button)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def get_emails(self):
        lines = self.emails_text.toPlainText().splitlines()
        # Filter out empty lines and strip whitespace
        return [line.strip() for line in lines if line.strip()]

# -------------------------
# Main Window (REVISED methods for account management and logging)
# -------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Google Workspace Manager - GBot V8")
        self.google_api = GoogleAPI()
        self.dark_theme_enabled = False
        self.stop_sending_emails = False
        
        self.initial_accounts_loaded = False # New flag to track if accounts are loaded

        self.initMenu()
        self.initUI()
        self.apply_stylesheet(modern_stylesheet_light)
        
        # Call load_accounts_to_ui AFTER initUI and BEFORE the delayed check
        self.load_accounts_to_ui() # Populate UI from whatever ACCOUNTS has initially
        
        self.setup_auto_refresh()

        app_instance = QApplication.instance()
        if app_instance:
            app_instance.main_window_ref = self

        # Instead of immediate check, schedule a delayed check
        # 60000 ms = 60 seconds. Adjust as needed.
        # This timer will fire once after the specified delay.
        QTimer.singleShot(80000, self.check_initial_accounts_status)
        self.log_message("MainWindow initialized. Scheduled initial account status check.", self.error_text)


        self.driver = None
        self.last_downloaded_bulk_csv_path = None

    def check_initial_accounts_status(self):
        """
        Checks the status of ACCOUNTS after a delay and shows a warning if needed.
        This method is called by QTimer.singleShot.
        """
        global ACCOUNTS, _last_accounts_mtime # Access globals to check their current state

        # The self.initial_accounts_loaded flag isn't strictly necessary here anymore
        # as we directly check the global ACCOUNTS state after the delay.
        # initialize_accounts() should have completed or failed by now.

        if not ACCOUNTS:
            logging.warning("Delayed Check: No account configurations found or loaded.")
            QMessageBox.warning(self, "Account Load Issue",
                                "Could not load account configurations during startup.\n"
                                "Please use 'Refresh List' or add accounts manually. Check app.log for "
                                "SFTP/file errors.")
        elif _last_accounts_mtime is None and os.path.exists(LOCAL_ACCOUNTS_FILE): # Indicates loaded from local
            logging.warning("Delayed Check: Loaded accounts from local cache. Data may be outdated.")
            QMessageBox.warning(self, "Stale Data Possible",
                                "Loaded accounts from local cache as server was unreachable or data was corrupt.\n"
                                "Data might be outdated. Please use 'Refresh List' when possible.")
        else:
            logging.info("Delayed Check: Accounts seem to be loaded successfully from server or local non-fallback.")
            # If accounts were loaded successfully by initialize_accounts or auto_refresh before this check,
            # self.load_accounts_to_ui() would have already populated the UI.
            # We can call it again to be sure, or assume it's up-to-date.
            # For safety, let's ensure UI reflects the LATEST state of ACCOUNTS.
            self.load_accounts_to_ui()

    @pyqtSlot(str)
    def _show_backup_warning_message(self, message):
        QMessageBox.warning(self, "Backup Warning", message)

    # Optional: Slot for generic critical messages if needed by other threads
    # @pyqtSlot(str, str)
    # def _show_critical_message(self, title, message):
    #     QMessageBox.critical(self, title, message)

    def setup_auto_refresh(self, interval_ms=60_000): # 1 minute
        self.auto_refresh_timer = QTimer(self)
        self.auto_refresh_timer.timeout.connect(self.auto_refresh_accounts)
        self.auto_refresh_timer.start(interval_ms)
        logging.info(f"Auto-refresh for accounts.json scheduled every {interval_ms // 1000} seconds.")

    def auto_refresh_accounts(self):
        global ACCOUNTS, _last_accounts_mtime, _last_loaded_accounts_path
        logging.debug("Auto-refresh: Checking server for accounts.json updates...")
        try:
            refreshed_accounts, new_mtime, loaded_path = load_accounts_from_server_with_mtime()
            if new_mtime is not None and new_mtime != _last_accounts_mtime:
                ACCOUNTS = refreshed_accounts
                _last_accounts_mtime = new_mtime
                _last_loaded_accounts_path = loaded_path
                self.load_accounts_to_ui()
                logging.info(f"Auto-refreshed accounts.json (mtime={new_mtime}, path={loaded_path}). UI updated.")
            elif new_mtime is None and _last_accounts_mtime is not None:
                 logging.warning("Auto-refresh: accounts.json may have become inaccessible on server.")
        except ConnectionError as e_conn:
            logging.warning(f"Auto-refresh: SFTP connection error: {e_conn}. Skipping update.")
        except Exception as e:
            logging.error(f"Auto-refresh: Unexpected error: {e}", exc_info=True)
    def clear_subdomain_display_ui(self):
        self.subdomain_display.clear()
        self.log_message("Subdomain display cleared.", self.error_text)

    def load_accounts_to_ui(self):
        """Loads accounts from the global ACCOUNTS dict into UI elements.
           Displays accounts in reversed order of keys (simulating last added first).
        """
        if hasattr(self, 'account_dropdown') and hasattr(self, 'accounts_listbox'):
            current_dropdown_text = self.account_dropdown.currentText()
            selected_listbox_items_text = [self.accounts_listbox.item(i).text() for i in range(self.accounts_listbox.count()) if self.accounts_listbox.item(i).isSelected()]

            self.account_dropdown.clear()
            self.accounts_listbox.clear()

            # Get account names and reverse the list for "last added first" display
            # This relies on Python 3.7+ dictionary insertion order preservation.
            account_names_ordered = list(ACCOUNTS.keys())
            account_names_reversed = list(reversed(account_names_ordered)) # Reverse here

            self.account_dropdown.addItems(account_names_reversed) # Add reversed to dropdown
            self.accounts_listbox.addItems(account_names_reversed) # Add reversed to listbox

            if current_dropdown_text in account_names_reversed: # Check against reversed list
                self.account_dropdown.setCurrentText(current_dropdown_text)
            elif account_names_reversed:
                self.account_dropdown.setCurrentIndex(0)

            for text_to_select in selected_listbox_items_text:
                items_found = self.accounts_listbox.findItems(text_to_select, Qt.MatchExactly)
                if items_found:
                    items_found[0].setSelected(True)

            logging.info(f"UI updated with {len(account_names_reversed)} accounts (reversed order) from global ACCOUNTS.")
        else:
            logging.warning("Attempted to load accounts to UI before UI elements are initialized.")


    def refresh_accounts(self):
        global ACCOUNTS, _last_accounts_mtime, _last_loaded_accounts_path
        logging.info("User triggered: Refreshing accounts from server...")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            refreshed_accounts, new_mtime, loaded_path = load_accounts_from_server_with_mtime()
            if new_mtime is not None:
                ACCOUNTS = refreshed_accounts
                _last_accounts_mtime = new_mtime
                _last_loaded_accounts_path = loaded_path
                self.load_accounts_to_ui()
                QMessageBox.information(self, "Success", f"Accounts refreshed from server.\nLoaded {len(ACCOUNTS)} accounts from {loaded_path or 'N/A'}.")
                logging.info(f"Accounts refreshed via UI. New mtime: {new_mtime}, path: {loaded_path}")
            else:
                ACCOUNTS = {}; _last_accounts_mtime = None; _last_loaded_accounts_path = None
                self.load_accounts_to_ui()
                QMessageBox.warning(self, "Refresh Issue", "Could not load accounts from server. List cleared. Check connection/logs.")
                logging.warning("Refresh failed: Server unreachable or file corrupt. ACCOUNTS cleared.")
        except ConnectionError as e_conn:
             logging.error(f"SFTP Connection Error during manual refresh: {e_conn}")
             QMessageBox.critical(self, "Refresh Error", f"Failed to connect to server: {e_conn}\nDisplaying potentially stale data.")
             self.load_accounts_to_ui() # Show current (possibly stale) data
        except Exception as e:
            logging.error(f"Error refreshing accounts: {e}", exc_info=True)
            QMessageBox.critical(self, "Refresh Error", f"Unexpected error during refresh: {e}\nDisplaying potentially stale data.")
            self.load_accounts_to_ui()
        finally:
            QApplication.restoreOverrideCursor()

    def log_message(self, msg, log_widget=None):
        # Default to self.error_text (SMTP log on Tab 2) if no specific widget given
        # Fallback to bulk_change_log_text if error_text doesn't exist
        if log_widget is None:
            log_widget = getattr(self, 'error_text', None)
            if not log_widget and hasattr(self, 'bulk_change_log_text'):
                log_widget = self.bulk_change_log_text
            elif not log_widget: # Ultimate fallback
                 print(f"Log Widget Error (msg: {msg})")
                 logging.info(f"[Console Log]: {msg}")
                 return

        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_msg = f"[{timestamp}] {msg}"
        try:
             QMetaObject.invokeMethod(log_widget, "appendPlainText", Qt.QueuedConnection, Q_ARG(str, formatted_msg))
        except Exception as e:
             print(f"Error logging to GUI: {e}. Message: {formatted_msg}")
        logging.info(msg)

    def _handle_account_modification(self, modification_type, account_name=None, new_creds=None, parsed_accounts_for_auto_add=None):
        global ACCOUNTS, _last_accounts_mtime, _last_loaded_accounts_path
        log_prefix_msg = f"Op: {modification_type}" + (f", Acc: {account_name}" if account_name else "")
        # Log to self.error_text (SMTP log) for general account operations
        self.log_message(f"--- Starting Account Mod --- {log_prefix_msg}", self.error_text)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        changes_made_in_memory = False

        try:
            server_data_on_read, read_mtime, path_read_from = load_accounts_from_server_with_mtime()
            if read_mtime is None:
                msg = "Cannot perform safe mod. Server mtime unknown (down, file missing/corrupt). Refresh & retry."
                logging.warning(f"{log_prefix_msg}: {msg}")
                QMessageBox.warning(self, "Operation Skipped", msg)
                ACCOUNTS = server_data_on_read or {}; _last_accounts_mtime = None; _last_loaded_accounts_path = None
                self.load_accounts_to_ui(); QApplication.restoreOverrideCursor(); return False

            accounts_to_write = server_data_on_read.copy()

            if modification_type == "add_manual":
                if account_name in accounts_to_write and accounts_to_write[account_name] != new_creds:
                    reply = QMessageBox.question(self, 'Confirm Overwrite', f"Acc '{account_name}' exists with diff creds. Overwrite?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                    if reply == QMessageBox.Yes: accounts_to_write[account_name] = new_creds; changes_made_in_memory = True; self.log_message(f"Marked '{account_name}' for update.", self.error_text)
                    else: self.log_message(f"Overwrite cancelled for '{account_name}'.", self.error_text)
                elif account_name not in accounts_to_write : # New or same creds if exists
                    accounts_to_write[account_name] = new_creds; changes_made_in_memory = True; self.log_message(f"Marked new/updated '{account_name}'.", self.error_text)
                else: # Exists with same creds
                    self.log_message(f"Acc '{account_name}' exists with same creds. No change.", self.error_text); QMessageBox.information(self, "No Change", f"Acc '{account_name}' exists with same creds.")

            elif modification_type == "delete":
                if account_name in accounts_to_write: del accounts_to_write[account_name]; changes_made_in_memory = True; self.log_message(f"Marked '{account_name}' for deletion.", self.error_text)
                else: self.log_message(f"Acc '{account_name}' not in server data.", self.error_text); QMessageBox.information(self, "Not Found", f"Acc '{account_name}' not found.")

            elif modification_type == "auto_add":
                merged_count = 0
                for email, creds_auto in parsed_accounts_for_auto_add.items():
                    if email not in accounts_to_write: accounts_to_write[email] = creds_auto; changes_made_in_memory = True; merged_count +=1; self.log_message(f"Auto-add: Marking new '{email}'.", self.error_text)
                    else: self.log_message(f"Auto-add: Acc '{email}' exists, skipped.", self.error_text)
                if merged_count == 0 and not changes_made_in_memory: self.log_message("Auto-add: No new accounts to merge.", self.error_text); QMessageBox.information(self, "No New Accounts", "All accounts from JSONs already exist or no valid JSONs found.")


            if not changes_made_in_memory:
                ACCOUNTS = server_data_on_read; _last_accounts_mtime = read_mtime; _last_loaded_accounts_path = path_read_from
                self.load_accounts_to_ui(); QApplication.restoreOverrideCursor(); return True

            target_write_path = path_read_from
            current_server_mtime = check_server_mtime(target_write_path)
            if current_server_mtime is None:
                msg = "Server file disappeared/error checking mtime pre-save. Aborting."; self.log_message(f"ERROR: {msg}", self.error_text); QMessageBox.critical(self, "Save Error", msg); self.refresh_accounts(); QApplication.restoreOverrideCursor(); return False
            if current_server_mtime != read_mtime:
                msg = f"CONFLICT: Server file changed (mtime {current_server_mtime} vs read {read_mtime}). Op aborted."; self.log_message(msg, self.error_text); QMessageBox.warning(self, "Conflict Detected", "Account config modified by another process.\nRefresh List & retry."); self.refresh_accounts(); QApplication.restoreOverrideCursor(); return False

            self.log_message(f"No conflict (mtime: {current_server_mtime}). Saving to {target_write_path}...", self.error_text)
            backup_local_file(LOCAL_ACCOUNTS_FILE)
            with open(LOCAL_ACCOUNTS_FILE, 'w') as f_local: json.dump(accounts_to_write, f_local, indent=4)
            save_to_server(LOCAL_ACCOUNTS_FILE, target_write_path)
            ACCOUNTS = accounts_to_write; _last_accounts_mtime = check_server_mtime(target_write_path); _last_loaded_accounts_path = target_write_path
            self.load_accounts_to_ui()
            success_msg = {"add_manual": f"Acc '{account_name}' processed.", "delete": f"Acc '{account_name}' deleted.", "auto_add": f"Auto-add done. {len(parsed_accounts_for_auto_add or {})} accs considered."}
            QMessageBox.information(self, "Success", success_msg.get(modification_type, "Op successful.")); self.log_message(f"Saved changes for {modification_type}.", self.error_text)
            QApplication.restoreOverrideCursor(); return True
        except ConnectionError as e_sftp:
            err_msg = f"SFTP Error during acc mod: {e_sftp}"; self.log_message(f"ERROR: {err_msg}", self.error_text); QMessageBox.critical(self, "SFTP Error", err_msg); self.load_accounts_to_ui()
        except Exception as e_mod:
            err_msg = f"Unexpected error during acc mod: {e_mod}"; logging.error(err_msg, exc_info=True); self.log_message(f"ERROR: {err_msg}", self.error_text); QMessageBox.critical(self, "Mod Error", err_msg); self.load_accounts_to_ui()
        finally: QApplication.restoreOverrideCursor()
        return False

    def copy_selected_suspended_users(self):
        """Copies the email addresses of selected users from the suspended_users_list to the clipboard."""
        selected_items = self.suspended_users_list.selectedItems()
        if not selected_items:
            self.log_message("No suspended users selected to copy.", self.error_text)
            QMessageBox.information(self, "Nothing Selected", "Please select users from the suspended list to copy.")
            return

        emails_to_copy = [item.text() for item in selected_items]
        clipboard = QApplication.clipboard()
        clipboard.setText("\n".join(emails_to_copy)) # Copy as newline-separated string

        self.log_message(f"Copied {len(emails_to_copy)} selected suspended user(s) to clipboard.", self.error_text)
        QMessageBox.information(self, "Copied", f"{len(emails_to_copy)} suspended user email(s) copied to clipboard.")


    def apply_stylesheet(self, stylesheet):
        """Applies the stylesheet and updates theme state."""
        self.setStyleSheet(stylesheet)
        self.dark_theme_enabled = (stylesheet == modern_stylesheet_dark)

    def sftp_connect(self):
        # This can be simplified if @_sftp_operation handles all connections
        # Kept here for now if direct SFTPClient is needed elsewhere
        try:
            transport = paramiko.Transport((SERVER_ADDRESS, SERVER_PORT))
            transport.connect(username=USERNAME, password=PASSWORD)
            sftp = paramiko.SFTPClient.from_transport(transport)
            logging.info(f"Successfully connected to SFTP server {SERVER_ADDRESS}:{SERVER_PORT}")
            return sftp
        except Exception as e:
            logging.error(f"Failed to connect to SFTP server: {e}", exc_info=True)
            QMessageBox.critical(self, "SFTP Error", f"SFTP connection failed: {e}")
            return None



    def init_driver(self, headless=False):
        if self.driver:
            logging.warning("Driver already initialized. Closing existing one.")
            try:
                self.driver.quit()
            except Exception as e:
                logging.error(f"Error quitting existing driver: {e}")
            self.driver = None

        logging.info(f"Initializing WebDriver (Headless: {headless})")
        try:
            chrome_options = uc.ChromeOptions() # Use undetected_chromedriver options
            # Common options
            chrome_options.add_argument("--disable-search-engine-choice-screen") # Bypass choice screen if it appears
            chrome_options.add_argument("--disable-dev-shm-usage") # Overcome limited resource problems
            chrome_options.add_argument("--no-sandbox") # Bypass OS security model, REQUIRED for Docker/root
            chrome_options.add_argument("--disable-blink-features=AutomationControlled") # Try to avoid detection
            chrome_options.add_argument('--log-level=3')  # Suppress excessive console logs from Chrome/ChromeDriver
            chrome_options.add_argument('--disable-gpu') # Often needed for headless or server environments

            # User agent spoofing (optional, might help avoid detection)
            # chrome_options.add_argument(f'user-agent={Faker().user_agent()}')

            if headless:
                chrome_options.add_argument("--headless=new") # Use the new headless mode
                chrome_options.add_argument("--window-size=1920,1080") # Set window size for headless

            # Experimental options to appear more human (use with caution)
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)

            # Set path for user data directory (optional, can help maintain sessions/cookies if needed between runs, but usually cleared on logout)
            # user_data_dir = os.path.join(os.getcwd(), "chrome_profile")
            # chrome_options.add_argument(f"--user-data-dir={user_data_dir}")

            # Initialize undetected_chromedriver
            self.driver = uc.Chrome(options=chrome_options, version_main=119) # Specify version if needed, or let it auto-detect
            # Set implicit wait (optional, waits for elements globally if not found immediately)
            # self.driver.implicitly_wait(5)
            logging.info("WebDriver initialized successfully.")

        except WebDriverException as wde:
             logging.error(f"WebDriverException during initialization: {wde}")
             # Check for common issues
             if "chromedriver executable needs to be in PATH" in str(wde):
                 QMessageBox.critical(self, "Driver Error", "ChromeDriver executable not found or not in PATH. Please ensure it's installed correctly.")
             elif "session not created" in str(wde):
                  QMessageBox.critical(self, "Driver Error", f"Session not created. Chrome version might be incompatible or browser failed to start. Check logs.\nError: {wde}")
             else:
                 QMessageBox.critical(self, "Driver Error", f"Failed to initialize WebDriver: {wde}")
             self.driver = None # Ensure driver is None if init fails
        except Exception as e:
            logging.error(f"Unexpected error initializing WebDriver: {e}", exc_info=True)
            QMessageBox.critical(self, "Driver Error", f"An unexpected error occurred initializing WebDriver: {e}")
            self.driver = None

    def logout(self):
        """Log out of the current Google session and clear cookies."""
        if not self.driver:
            logging.warning("Logout called but driver is not initialized.")
            return

        try:
            # Navigate directly to Google's main logout page
            logout_url = "https://accounts.google.com/Logout?continue=https://google.com" # Redirect to google.com after logout
            logging.info(f"Navigating to logout URL: {logout_url}")
            self.driver.get(logout_url)

            # Wait for potential redirects or confirmation page (adjust timeout as needed)
            time.sleep(3) # Simple wait, might need WebDriverWait for specific elements if logout page changes

            # Aggressively clear cookies for all domains Google might use
            logging.info("Clearing all cookies...")
            self.driver.delete_all_cookies()
            time.sleep(1) # Short pause after clearing cookies

            # Optionally, clear local storage and session storage
            # logging.info("Clearing local and session storage...")
            # self.driver.execute_script("window.localStorage.clear();")
            # self.driver.execute_script("window.sessionStorage.clear();")
            # time.sleep(1)

            # Verify logout by checking current URL or title (optional but good practice)
            current_url = self.driver.current_url
            logging.info(f"Current URL after logout attempt: {current_url}")
            if "accounts.google.com" in current_url and "signin" in current_url:
                logging.info("Successfully logged out (redirected to sign-in page).")
            elif "google.com" in current_url and "accounts.google.com" not in current_url:
                 logging.info("Successfully logged out (redirected to google.com).")
            else:
                logging.warning("Logout URL or state unclear after logout attempt. Cookies cleared.")

        except WebDriverException as wde:
             logging.error(f"WebDriverException during logout: {wde}. Driver session might be invalid.")
             # Optionally try to quit the driver if it seems broken
             # self.close_driver()
        except Exception as e:
            logging.error(f"Unexpected error during logout: {e}", exc_info=True)


    def close_driver(self):
         """Safely close the WebDriver."""
         if self.driver:
             logging.info("Closing WebDriver...")
             try:
                 self.driver.quit()
                 logging.info("WebDriver closed.")
             except Exception as e:
                 logging.error(f"Error closing WebDriver: {e}")
             finally:
                 self.driver = None # Ensure driver is set to None


    def initMenu(self):
        menubar = self.menuBar()
        # File Menu (Optional - can add Exit, etc.)
        # fileMenu = menubar.addMenu("File")
        # exitAction = QAction("Exit", self)
        # exitAction.triggered.connect(self.close)
        # fileMenu.addAction(exitAction)

        viewMenu = menubar.addMenu("View")
        self.toggleThemeAction = QAction("Toggle Dark/Light Theme", self)
        self.toggleThemeAction.triggered.connect(self.toggle_dark_theme)
        viewMenu.addAction(self.toggleThemeAction)

    def toggle_dark_theme(self):
        if self.dark_theme_enabled:
            self.apply_stylesheet(modern_stylesheet_light)
        else:
            self.apply_stylesheet(modern_stylesheet_dark)

    def initUI(self):
        # --- Largely unchanged, ensure correct methods are called ---
        self.tabs = QTabWidget()
        account_management_tab = self.create_account_management_tab()
        smtp_csv_tab = self.create_smtp_csv_tab()
        user_domain_mgmt_tab = self.create_user_domain_management_tab()
        bulk_domain_change_tab = self.create_bulk_domain_change_tab()

        self.tabs.addTab(account_management_tab, "⚙️ Account & User Mgmt")
        self.tabs.addTab(user_domain_mgmt_tab, "👤➕✏️ User Create/Delete/Domain")
        self.tabs.addTab(bulk_domain_change_tab, "🔄 Bulk Domain Change")
        self.tabs.addTab(smtp_csv_tab, "✉️ SMTP & CSV Gen")

        self.setCentralWidget(self.tabs)
        self.setGeometry(100, 100, 1000, 800)



    def initialize_batch_counters(self):
        """Resets counters before starting a batch process."""
        self.batch_success_count = 0
        self.batch_fail_count = 0
        self.batch_total_processed_in_callbacks = 0 # Track how many callbacks completed

    def batch_callback(self, request_id, response, exception):
        """Callback function for BatchHttpRequest."""
        self.batch_total_processed_in_callbacks += 1 # Increment processed counter

        # Check if the GUI log widget still exists
        log_widget = self.bulk_change_log_text
        if not log_widget:
             logging.error("Batch callback executed but log widget is gone.")
             return # Cannot log to GUI

        current_email = request_id # We used the email as the request ID

        if exception:
            self.batch_fail_count += 1
            # Parse the HttpError for details
            error_details = f"API Error ({exception.resp.status} {exception.resp.reason})"
            try:
                error_content = exception.content.decode('utf-8')
                error_json = json.loads(error_content)
                if 'error' in error_json and 'message' in error_json['error']:
                    error_details += f": {error_json['error']['message']}"
                else:
                    error_details += f" - Raw: {error_content[:200]}" # Show partial raw error
            except Exception:
                error_details += f" - Error: {exception}" # Fallback

            log_msg = f"  FAILED (Batch): Update for {current_email}. {error_details}"
            # Log to GUI thread-safely
            QMetaObject.invokeMethod(log_widget, "appendPlainText", Qt.QueuedConnection, Q_ARG(str, log_msg))
            logging.error(f"Batch update failed for {current_email}: {exception}")
        else:
            self.batch_success_count += 1
            new_email = response.get('primaryEmail', 'N/A') # Get the resulting email
            log_msg = f"  SUCCESS (Batch): Updated {current_email} -> {new_email}"
            # Log to GUI thread-safely
            QMetaObject.invokeMethod(log_widget, "appendPlainText", Qt.QueuedConnection, Q_ARG(str, log_msg))
            logging.info(f"Batch update successful for {current_email}")

    def change_domain_for_all_users(self):
        """
        Fetches all users via API and updates domain for matching, non-admin users
        using Batch API.
        """
        if not self.google_api.service:
            QMessageBox.warning(self, "Not Authenticated", "Please authenticate an account first.")
            return

        # Get inputs from the new UI elements
        current_domain = self.all_users_current_domain_entry.text().strip()
        new_domain = self.all_users_new_domain_entry.text().strip()

        # --- Input Validation ---
        if not current_domain or '.' not in current_domain:
            QMessageBox.warning(self, "Input Error", "Please enter a valid 'Current Domain Suffix'.")
            return
        if not new_domain or '.' not in new_domain:
            QMessageBox.warning(self, "Input Error", "Please enter a valid 'New Domain Suffix'.")
            return
        if current_domain.lower() == new_domain.lower():
             QMessageBox.warning(self, "Input Error", "Current and New domains are the same.")
             return

        # --- Confirmation ---
        reply = QMessageBox.question(
            self, 'Confirm MAJOR Domain Change',
            f"!! WARNING !!\n\nThis will attempt to change the domain suffix from\n"
            f"'@{current_domain}' to '@{new_domain}'\n"
            f"for potentially ALL users in the account ending with '@{current_domain}' "
            f"(excluding any starting with 'admin@').\n\n"
            f"This action is irreversible through this tool.\n\n"
            f"Are you absolutely sure you want to proceed?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.No:
            self.log_message("Change domain for all users cancelled.", self.bulk_change_log_text)
            return

        # --- Processing ---
        self.log_message(f"\n--- Starting Change Domain for ALL Users (Non-CSV, Batch Mode) ---", self.bulk_change_log_text)
        self.log_message(f"Target Change: '@{current_domain}' -> '@{new_domain}' (Excluding admin@)", self.bulk_change_log_text)
        QApplication.setOverrideCursor(Qt.WaitCursor)

        self.initialize_batch_counters() # Reset batch counters
        users_fetched = 0
        requests_queued_total = 0
        skipped_admin_count = 0
        skipped_domain_mismatch = 0
        requests_in_current_batch = 0
        BATCH_SIZE = 100 # Reuse batch size constant

        try:
            # --- Initialize Batch ---
            batch = self.google_api.service.new_batch_http_request(callback=self.batch_callback)
            page_token = None

            # --- Fetch users via API and build batches ---
            self.log_message("Fetching users from API...", self.bulk_change_log_text)
            while True:
                 results = self.google_api.service.users().list(
                     customer='my_customer',
                     orderBy='email',
                     maxResults=500, # Fetch in pages
                     projection='basic', # Only need email
                     fields='nextPageToken,users(primaryEmail)', # Optimize fields
                     pageToken=page_token
                 ).execute()

                 users_in_page = results.get('users', [])
                 users_fetched += len(users_in_page)
                 self.log_message(f"Fetched page, total users processed so far: {users_fetched}", self.bulk_change_log_text)
                 QApplication.processEvents()

                 for user in users_in_page:
                     current_email = user.get('primaryEmail', '').strip()
                     expected_suffix = f"@{current_domain}"

                     # Validate email and check suffix
                     if not current_email or '@' not in current_email:
                          continue # Skip invalid emails from API? Unlikely but safe.
                     if not current_email.lower().endswith(expected_suffix.lower()):
                          skipped_domain_mismatch += 1
                          continue # Skip if domain doesn't match

                     # Check if admin
                     if current_email.lower().startswith('admin@'):
                          skipped_admin_count += 1
                          continue # Skip admin user

                     # Construct new email and add to batch
                     try:
                         alias = current_email[:-len(expected_suffix)]
                         new_email = f"{alias}@{new_domain}"
                         update_payload = {'primaryEmail': new_email}

                         requests_queued_total += 1
                         batch.add(
                             self.google_api.service.users().update(userKey=current_email, body=update_payload),
                             request_id=current_email # Use email as ID
                         )
                         requests_in_current_batch += 1

                         # Execute batch if full
                         if requests_in_current_batch >= BATCH_SIZE:
                             self.log_message(f"Executing batch of {requests_in_current_batch} requests (Total queued: {requests_queued_total})...", self.bulk_change_log_text)
                             QApplication.processEvents()
                             try: batch.execute()
                             except Exception as batch_exec_err:
                                  self.log_message(f"ERROR executing batch: {batch_exec_err}", self.bulk_change_log_text)
                                  logging.error(f"Batch execution error (non-CSV): {batch_exec_err}", exc_info=True)
                             batch = self.google_api.service.new_batch_http_request(callback=self.batch_callback)
                             requests_in_current_batch = 0
                             time.sleep(0.5) # Pause between batches

                     except Exception as e_row:
                          self.log_message(f"Error preparing request for '{current_email}': {e_row}", self.bulk_change_log_text)
                          # Consider how to count this error - maybe add a prep_fail_count?


                 page_token = results.get('nextPageToken')
                 if not page_token:
                     break # Exit loop if no more pages

            # --- Execute final batch ---
            if requests_in_current_batch > 0:
                self.log_message(f"Executing final batch of {requests_in_current_batch} requests (Total queued: {requests_queued_total})...", self.bulk_change_log_text)
                QApplication.processEvents()
                try: batch.execute()
                except Exception as batch_exec_err:
                     self.log_message(f"ERROR executing final batch: {batch_exec_err}", self.bulk_change_log_text)
                     logging.error(f"Final Batch execution error (non-CSV): {batch_exec_err}", exc_info=True)


            self.log_message(f"All {requests_queued_total} potential update requests queued and batches executed. Waiting for callbacks...", self.bulk_change_log_text)
            time.sleep(2) # Wait briefly for callbacks


            # --- Final Summary ---
            summary_msg = (
                f"\n--- Change Domain for All Users (Non-CSV) Finished ---\n"
                f"Total Users Fetched from API: {users_fetched}\n"
                f"Requests Queued for Update: {requests_queued_total}\n"
                f"Successfully Updated (via callbacks): {self.batch_success_count}\n"
                f"Failed Updates (via callbacks): {self.batch_fail_count}\n"
                f"Skipped (Admin Users): {skipped_admin_count}\n"
                f"Skipped (Domain Mismatch/Other): {skipped_domain_mismatch}" # Includes initial mismatches
            )
            if self.batch_total_processed_in_callbacks != requests_queued_total:
                 summary_msg += f"\n\nWarning: Callback count ({self.batch_total_processed_in_callbacks}) doesn't match queued requests ({requests_queued_total}). Results might be incomplete."

            self.log_message(summary_msg, self.bulk_change_log_text)
            QMessageBox.information(self, "Process Complete", summary_msg.replace("\n---", "\n").strip())


        except HttpError as http_err:
             error_msg = f"API Error fetching users: {http_err}"
             logging.error(error_msg, exc_info=True)
             self.log_message(f"FATAL ERROR during user fetch: {error_msg}", self.bulk_change_log_text)
             QMessageBox.critical(self, "API Error", error_msg)
        except Exception as e:
            error_msg = f"An unexpected error occurred during the 'Change Domain for All' process: {e}"
            logging.error(error_msg, exc_info=True)
            self.log_message(f"FATAL ERROR: {error_msg}", self.bulk_change_log_text)
            QMessageBox.critical(self, "Processing Error", error_msg)
        finally:
            QApplication.restoreOverrideCursor()

    # -------------------------
    # Tab 1: Account Management
    # -------------------------
    def create_account_management_tab(self):
        # (Keep existing implementation)
        container_widget = QWidget()
        main_layout = QVBoxLayout(container_widget)
        main_layout.setContentsMargins(5, 5, 5, 5) # Reduce margins slightly

        # --- Account Controls Group ---
        account_group = QGroupBox("👤 Account Selection & Authentication")
        account_layout = QVBoxLayout(account_group)

        # Row 1: Dropdown, Auth buttons
        auth_row1_layout = QHBoxLayout()
        self.account_dropdown = QComboBox()
        self.account_dropdown.setToolTip("Select a previously added account to authenticate.")
        auth_row1_layout.addWidget(QLabel("Select Account:"))
        auth_row1_layout.addWidget(self.account_dropdown, 1) # Stretch dropdown

        self.auth_dropdown_btn = QPushButton("🔑 Authenticate Selected")
        self.auth_dropdown_btn.setToolTip("Authenticate using the account selected in the dropdown.")
        self.auth_dropdown_btn.clicked.connect(self.authenticate_dropdown)
        auth_row1_layout.addWidget(self.auth_dropdown_btn)

        self.login_from_file_btn = QPushButton("🔐 Login via Browser (login.txt)")
        self.login_from_file_btn.setToolTip("Login to accounts listed in <selected_account>/login.txt using Selenium.")
        self.login_from_file_btn.clicked.connect(self.login_from_file)
        auth_row1_layout.addWidget(self.login_from_file_btn)
        account_layout.addLayout(auth_row1_layout)

        # Row 2: Add, Refresh, Backup buttons
        manage_row_layout = QHBoxLayout()
        self.add_account_btn = QPushButton("➕ Add Manually")
        self.add_account_btn.setToolTip("Manually add a new account with its Client ID/Secret.")
        self.add_account_btn.clicked.connect(self.add_account_dialog)
        manage_row_layout.addWidget(self.add_account_btn)

        self.add_account_auto_btn = QPushButton("🔁 Add from Server JSON")
        self.add_account_auto_btn.setToolTip("Search for <email>.json files on the server and add corresponding accounts.")
        self.add_account_auto_btn.clicked.connect(self.add_account_from_json)
        manage_row_layout.addWidget(self.add_account_auto_btn)

        self.refresh_btn = QPushButton("🔄 Refresh List")
        self.refresh_btn.setToolTip("Reload the account list from the server's accounts.json.")
        self.refresh_btn.clicked.connect(self.refresh_accounts)
        manage_row_layout.addWidget(self.refresh_btn)

        self.backup_btn = QPushButton("💾 Backup Files")
        self.backup_btn.setToolTip("Backup local accounts.json and tokens.json to the Desktop backup folder.")
        self.backup_btn.clicked.connect(self.backup_files)
        manage_row_layout.addWidget(self.backup_btn)

        manage_row_layout.addStretch() # Push buttons left
        account_layout.addLayout(manage_row_layout)

        # Row 3: Search and Listbox for selection/deletion
        search_list_layout = QHBoxLayout()
        search_list_left_layout = QVBoxLayout() # Layout for search and list

        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Search accounts in list...")
        self.search_entry.textChanged.connect(self.search_accounts_in_listbox) # Connect search
        search_list_left_layout.addWidget(self.search_entry)

        self.accounts_listbox = QListWidget()
        self.accounts_listbox.setToolTip("List of configured accounts. Select one for deletion.")
        # self.accounts_listbox.currentItemChanged.connect(self.account_list_selection_changed) # Optional: sync dropdown
        search_list_left_layout.addWidget(self.accounts_listbox)

        search_list_layout.addLayout(search_list_left_layout, 3) # Give listbox more space

        # Buttons next to the listbox
        search_list_right_layout = QVBoxLayout()
        self.auth_listbox_btn = QPushButton("🔑 Authenticate\n(List Selection)") # Use listbox selection
        self.auth_listbox_btn.setToolTip("Authenticate using the account selected in the list below.")
        self.auth_listbox_btn.clicked.connect(self.authenticate_listbox) # Use listbox selection
        search_list_right_layout.addWidget(self.auth_listbox_btn)

        self.delete_account_btn = QPushButton("🗑️ Delete Account\n(List Selection)")
        self.delete_account_btn.setToolTip("Delete the selected account from the configuration.")
        self.delete_account_btn.clicked.connect(self.confirm_delete_account)
        search_list_right_layout.addWidget(self.delete_account_btn)
        search_list_right_layout.addStretch() # Align buttons top

        search_list_layout.addLayout(search_list_right_layout, 1) # Allocate space for buttons
        account_layout.addLayout(search_list_layout) # Add the search/list/buttons row

        main_layout.addWidget(account_group)

        # --- Splitter for User/Domain/Suspended ---
        splitter = QSplitter(Qt.Vertical) # Arrange sections vertically

        # --- User Management Group ---
        user_group = QGroupBox("🧑‍💻 User Listing & Basic Actions")
        user_layout = QVBoxLayout(user_group)
        user_actions_layout = QHBoxLayout()
        self.retrieve_users_btn = QPushButton("📊 Retrieve All Users")
        self.retrieve_users_btn.setToolTip("Fetch and display all users from the authenticated account.")
        self.retrieve_users_btn.clicked.connect(self.retrieve_active_users)
        user_actions_layout.addWidget(self.retrieve_users_btn)
        self.clear_list_btn = QPushButton("🧹 Clear List")
        self.clear_list_btn.setToolTip("Clear the user list display area.")
        self.clear_list_btn.clicked.connect(self.clear_user_list)
        user_actions_layout.addWidget(self.clear_list_btn)
        self.select_all_copy_btn = QPushButton("📋 Select All + Copy")
        self.select_all_copy_btn.setToolTip("Select all emails in the list and copy them to the clipboard.")
        self.select_all_copy_btn.clicked.connect(self.select_all_copy)
        user_actions_layout.addWidget(self.select_all_copy_btn)
        user_layout.addLayout(user_actions_layout)
        self.user_list_text = QTextEdit()
        self.user_list_text.setReadOnly(True)
        self.user_list_text.setToolTip("Displays retrieved users. Colors indicate status (Active/Suspended/Admin-like).")
        user_layout.addWidget(self.user_list_text)
        self.user_count_label = QLabel("Total Users: 0")
        user_layout.addWidget(self.user_count_label)
        pass_row = QHBoxLayout()
        self.password_entry = QLineEdit()
        self.password_entry.setPlaceholderText("New Password for ALL Listed Users")
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.password_entry.setToolTip("Enter a password to apply to ALL users currently shown in the list above.")
        pass_row.addWidget(self.password_entry, 1) # Stretch input
        self.update_password_btn = QPushButton("🔑 Update Password (All Listed)")
        self.update_password_btn.setToolTip("Update the password for ALL users currently displayed in the list.")
        self.update_password_btn.clicked.connect(self.update_password_for_listed_users) # Changed action
        pass_row.addWidget(self.update_password_btn)
        user_layout.addLayout(pass_row)
        splitter.addWidget(user_group) # Add user group to splitter

        # --- Domain Management Group ---
        domain_group = QGroupBox("🌐 Domain Info & Subdomain Utility")
        domain_layout = QVBoxLayout(domain_group)
        subdisp_layout = QVBoxLayout()
        subdisp_layout.addWidget(QLabel("Verified Domains & User Counts:"))
        self.subdomain_display = QTextEdit()
        self.subdomain_display.setReadOnly(True)
        self.subdomain_display.setToolTip("Shows verified domains, active status, and user counts.")
        self.subdomain_display.setPlaceholderText("Click 'Retrieve Domains' to view")
        # self.subdomain_display.setMaximumHeight(150) # MODIFICATION: Removed max height
        subdisp_layout.addWidget(self.subdomain_display)
        subdisp_btn_row = QHBoxLayout()
        self.retrieve_subdomains_button = QPushButton("🔍 Retrieve Domains")
        self.retrieve_subdomains_button.setToolTip("Fetch verified domains and user counts for the authenticated account.")
        self.retrieve_subdomains_button.clicked.connect(self.retrieve_subdomains)
        subdisp_btn_row.addWidget(self.retrieve_subdomains_button)
        self.clear_subdomains_button = QPushButton("🧹 Clear Display")
        self.clear_subdomains_button.setToolTip("Clear the domain display area.")
        # THIS IS THE CORRECTED LINE:
        self.clear_subdomains_button.clicked.connect(self.clear_subdomain_display_ui)
        subdisp_btn_row.addWidget(self.clear_subdomains_button)
        subdisp_btn_row.addStretch() # Push buttons left
        subdisp_layout.addLayout(subdisp_btn_row)
        domain_layout.addLayout(subdisp_layout) # Add display part
        splitter.addWidget(domain_group) # Add domain group to splitter

        # --- START OF REVISED SUSPENDED USERS GROUP ---
        suspend_group = QGroupBox("⛔ Suspended User Management")
        suspend_layout = QVBoxLayout(suspend_group) # Main vertical layout for this group

        # Horizontal layout for the buttons
        suspend_btn_row = QHBoxLayout()

        # Button 1: Load Suspended Users
        self.load_suspended_users_btn = QPushButton("🔍 Load Suspended Users")
        self.load_suspended_users_btn.setToolTip("Fetch and list all currently suspended users.")
        self.load_suspended_users_btn.clicked.connect(self.load_suspended_users)
        suspend_btn_row.addWidget(self.load_suspended_users_btn)

        # Button 2: Unsuspend Selected
        self.unsuspend_selected_btn = QPushButton("✅ Unsuspend Selected")
        self.unsuspend_selected_btn.setToolTip("Attempt to unsuspend the users selected in the list below.")
        self.unsuspend_selected_btn.clicked.connect(self.unsuspend_selected_users)
        suspend_btn_row.addWidget(self.unsuspend_selected_btn)

        # Button 3: Copy Selected Suspended Users
        self.copy_suspended_btn = QPushButton("📋 Copy Selected")
        self.copy_suspended_btn.setToolTip("Copy the email addresses of the selected suspended users to the clipboard.")
        self.copy_suspended_btn.clicked.connect(self.copy_selected_suspended_users)
        suspend_btn_row.addWidget(self.copy_suspended_btn) # Explicitly add to the button row

        suspend_layout.addLayout(suspend_btn_row) # Add the row of buttons to the group's main layout

        # List widget for suspended users
        self.suspended_users_list = QListWidget()
        self.suspended_users_list.setSelectionMode(QListWidget.ExtendedSelection)
        self.suspended_users_list.setToolTip("List of suspended users. Select users to unsuspend or copy.")
        suspend_layout.addWidget(self.suspended_users_list) # Add list below buttons

        splitter.addWidget(suspend_group) # Add the entire group to the main splitter
        # --- END OF REVISED SUSPENDED USERS GROUP ---

        # ... (rest of the create_account_management_tab method, e.g., adding splitter to main_layout, scroll_area) ...
        main_layout.addWidget(splitter)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(container_widget)
        return scroll_area









    # -------------------------
    # Tab 2: SMTP & CSV Generation (Minor adjustments possible)
    # -------------------------
    def create_smtp_csv_tab(self):
        # (Keep existing implementation)
        container_widget = QWidget()
        main_layout = QVBoxLayout(container_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)

        # --- SMTP Testing Group ---
        smtp_group = QGroupBox("✉️ SMTP Credential Tester")
        smtp_layout = QVBoxLayout(smtp_group)
        smtp_inputs_layout = QGridLayout()
        smtp_inputs_layout.addWidget(QLabel("SMTP Credentials (email:password, one per line):"), 0, 0, 1, 2)
        self.smtp_credentials_text = QPlainTextEdit()
        self.smtp_credentials_text.setPlaceholderText("user1@example.com:password123\nuser2@sample.net:anotherPass")
        self.smtp_credentials_text.setMinimumHeight(100)
        smtp_inputs_layout.addWidget(self.smtp_credentials_text, 1, 0, 1, 2)
        smtp_inputs_layout.addWidget(QLabel("Recipient Email:"), 2, 0)
        self.recipient_email_entry = QLineEdit()
        self.recipient_email_entry.setPlaceholderText("test-recipient@domain.com")
        smtp_inputs_layout.addWidget(self.recipient_email_entry, 2, 1)
        smtp_inputs_layout.addWidget(QLabel("SMTP Server:"), 3, 0)
        self.smtp_server_dropdown = QComboBox()
        self.smtp_server_dropdown.addItems(["smtp.gmail.com", "smtp-relay.gmail.com", "smtp.live.com", "smtp.office365.com", "smtp.mail.me.com", "smtp.comcast.net", "outgoing.verizon.net", "smtp.mail.yahoo.com", "smtp.cox.net", "mail.twc.com", "smtp.charter.net", "mail.optimum.net", "smtp-server.triad.rr.com", "smtpauth.earthlink.net", "smtp.ziggo.nl", "uit.telenet.be", "relay.skynet.be", "smtp.orange.fr", "smtp.sfr.fr", "smtp.free.fr", "smtp-mail.outlook.com"])
        self.smtp_server_dropdown.setEditable(True)
        smtp_inputs_layout.addWidget(self.smtp_server_dropdown, 3, 1)
        smtp_inputs_layout.addWidget(QLabel("Port (e.g., 587, 465):"), 4, 0)
        self.smtp_port_entry = QLineEdit()
        self.smtp_port_entry.setPlaceholderText("587")
        smtp_inputs_layout.addWidget(self.smtp_port_entry, 4, 1)
        smtp_layout.addLayout(smtp_inputs_layout)
        smtp_buttons_layout = QHBoxLayout()
        self.send_test_email_btn = QPushButton("▶️ Send Test Emails")
        self.send_test_email_btn.setToolTip("Attempt to send a test email from each credential provided.")
        self.send_test_email_btn.clicked.connect(self.send_test_email)
        smtp_buttons_layout.addWidget(self.send_test_email_btn)
        self.interrupt_send_btn = QPushButton("⏹️ Interrupt Sending")
        self.interrupt_send_btn.setToolTip("Stop the ongoing email sending process.")
        self.interrupt_send_btn.clicked.connect(self.interrupt_send)
        self.interrupt_send_btn.setEnabled(False)
        smtp_buttons_layout.addWidget(self.interrupt_send_btn)
        smtp_layout.addLayout(smtp_buttons_layout)
        smtp_layout.addWidget(QLabel("Results Log:"))
        self.error_text = QPlainTextEdit() # This is used by log_message fallback
        self.error_text.setReadOnly(True)
        self.error_text.setPlaceholderText("Results (Good, Bad, Errors) will appear here...")
        smtp_layout.addWidget(self.error_text, 1)
        self.clear_errors_btn = QPushButton("🧹 Clear Log & Reset Files")
        self.clear_errors_btn.setToolTip("Clear the log display and reset the output text files (Good.txt, Bad.txt, etc.).")
        self.clear_errors_btn.clicked.connect(self.clear_errors)
        smtp_layout.addWidget(self.clear_errors_btn)
        main_layout.addWidget(smtp_group)

        # --- CSV Generation Group ---
        csv_group = QGroupBox("🗒️ Generate Sample CSV for User Creation")
        csv_layout = QGridLayout(csv_group) # Use grid layout
        csv_layout.addWidget(QLabel("Number of Users:"), 0, 0)
        self.csv_num_users_entry = QLineEdit()
        self.csv_num_users_entry.setPlaceholderText("e.g., 50")
        csv_layout.addWidget(self.csv_num_users_entry, 0, 1)
        csv_layout.addWidget(QLabel("Domain:"), 1, 0)
        self.csv_domain_entry = QLineEdit()
        self.csv_domain_entry.setPlaceholderText("e.g., yourdomain.com")
        csv_layout.addWidget(self.csv_domain_entry, 1, 1)
        csv_layout.addWidget(QLabel("Password (for all):"), 2, 0)
        self.csv_password_entry = QLineEdit()
        self.csv_password_entry.setPlaceholderText("DefaultP@ssw0rd!")
        csv_layout.addWidget(self.csv_password_entry, 2, 1)
        self.generate_csv_btn = QPushButton("📄 Generate CSV File")
        self.generate_csv_btn.setToolTip("Create a CSV file with randomly generated user data for bulk upload.")
        self.generate_csv_btn.clicked.connect(self.generate_csv)
        csv_layout.addWidget(self.generate_csv_btn, 3, 0, 1, 2) # Span button across columns
        main_layout.addWidget(csv_group)
        main_layout.addStretch() # Push content upwards

        # --- Scroll Area ---
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(container_widget)
        return scroll_area

    def create_user_domain_management_tab(self):
        # (Keep existing implementation with the added delete section)
        container_widget = QWidget()
        main_layout = QVBoxLayout(container_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)

        # --- Create Users from CSV File Group ---
        csv_user_group = QGroupBox("📂 Create Users from CSV File")
        csv_user_layout = QVBoxLayout(csv_user_group)
        file_select_layout = QHBoxLayout()
        self.create_csv_file_entry = QLineEdit()
        self.create_csv_file_entry.setPlaceholderText("Click 'Browse' to select CSV file...")
        self.create_csv_file_entry.setReadOnly(True)
        file_select_layout.addWidget(self.create_csv_file_entry, 1)
        self.create_csv_browse_btn = QPushButton("📁 Browse...")
        self.create_csv_browse_btn.clicked.connect(self.browse_csv_for_creation)
        file_select_layout.addWidget(self.create_csv_browse_btn)
        csv_user_layout.addLayout(file_select_layout)
        self.csv_create_users_btn = QPushButton("🚀 Create Users from CSV")
        self.csv_create_users_btn.setToolTip("Create Google Workspace users based on the selected CSV file.")
        self.csv_create_users_btn.clicked.connect(self.bulk_create_users_from_csv)
        csv_user_layout.addWidget(self.csv_create_users_btn)
        main_layout.addWidget(csv_user_group)

        # --- Create Random Users Group ---
        random_user_group = QGroupBox("👤 Create Random Users")
        random_user_layout = QGridLayout(random_user_group)
        random_user_layout.addWidget(QLabel("Number of Users:"), 0, 0)
        self.random_user_count_entry = QLineEdit()
        self.random_user_count_entry.setPlaceholderText("e.g., 10")
        random_user_layout.addWidget(self.random_user_count_entry, 0, 1)
        random_user_layout.addWidget(QLabel("Domain:"), 1, 0)
        self.random_user_domain_entry = QLineEdit()
        self.random_user_domain_entry.setPlaceholderText("e.g., randomusers.org")
        random_user_layout.addWidget(self.random_user_domain_entry, 1, 1)
        self.random_create_users_btn = QPushButton("✨ Create Random Users")
        self.random_create_users_btn.setToolTip("Create the specified number of users with random names and a fixed password.")
        self.random_create_users_btn.clicked.connect(self.create_random_users)
        random_user_layout.addWidget(self.random_create_users_btn, 2, 0, 1, 2)
        main_layout.addWidget(random_user_group)

        # --- Change Domain for Specific Users Group ---
        domain_change_group = QGroupBox("✏️ Change Domain for Specific Users")
        domain_change_layout = QVBoxLayout(domain_change_group)
        domain_change_inputs = QGridLayout()
        domain_change_inputs.addWidget(QLabel("Current Domain Suffix:"), 0, 0)
        self.specific_current_domain_entry = QLineEdit()
        self.specific_current_domain_entry.setPlaceholderText("e.g., old-domain.com")
        domain_change_inputs.addWidget(self.specific_current_domain_entry, 0, 1)
        domain_change_inputs.addWidget(QLabel("New Domain Suffix:"), 1, 0)
        self.specific_new_domain_entry = QLineEdit()
        self.specific_new_domain_entry.setPlaceholderText("e.g., new-domain.com")
        domain_change_inputs.addWidget(self.specific_new_domain_entry, 1, 1)
        domain_change_layout.addLayout(domain_change_inputs)
        domain_change_layout.addWidget(QLabel("Enter Email Addresses (one per line):"))
        self.specified_users_text = QPlainTextEdit()
        self.specified_users_text.setPlaceholderText("user1@old-domain.com\nuser2@old-domain.com\n...")
        self.specified_users_text.setMinimumHeight(100)
        domain_change_layout.addWidget(self.specified_users_text)
        self.change_domain_specified_btn = QPushButton("🌍 Change Domain for These Users")
        self.change_domain_specified_btn.setToolTip("Change the domain for only the emails listed above.")
        self.change_domain_specified_btn.clicked.connect(self.change_domain_specified_users)
        domain_change_layout.addWidget(self.change_domain_specified_btn)
        main_layout.addWidget(domain_change_group)

        # --- Delete Specific Users Group ---
        delete_user_group = QGroupBox("🗑️ Delete Specific Users")
        delete_user_layout = QVBoxLayout(delete_user_group)
        delete_user_layout.addWidget(QLabel("Enter Email Addresses to Delete (one per line):"))
        self.delete_users_text = QPlainTextEdit()
        self.delete_users_text.setPlaceholderText("user-to-delete1@example.com\nuser-to-delete2@example.com\n...")
        self.delete_users_text.setMinimumHeight(100)
        delete_user_layout.addWidget(self.delete_users_text)
        self.delete_specified_users_btn = QPushButton("❌ Delete These Users")
        self.delete_specified_users_btn.setToolTip("Permanently delete the users listed above. This action is irreversible!")
        self.delete_specified_users_btn.clicked.connect(self.delete_specified_users)
        delete_user_layout.addWidget(self.delete_specified_users_btn)
        main_layout.addWidget(delete_user_group)

        main_layout.addStretch() # Push content up

        # --- Scroll Area ---
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(container_widget)
        return scroll_area

    def create_bulk_domain_change_tab(self):
        # (Keep existing implementation)
        container_widget = QWidget()
        main_layout = QVBoxLayout(container_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # --- CSV Workflow ---
        csv_workflow_group = QGroupBox("Workflow 1: Change Domain using CSV File")
        csv_workflow_layout = QVBoxLayout(csv_workflow_group)
        download_group = QGroupBox("Step 1.1: Download Current Users to CSV")
        download_layout = QVBoxLayout(download_group)
        self.download_users_csv_btn = QPushButton("📥 Download All Users")
        self.download_users_csv_btn.setToolTip("Downloads a CSV of all users from the currently authenticated account.\nIncludes 'Current Email' and 'New Email' columns.")
        self.download_users_csv_btn.clicked.connect(self.download_users_for_bulk_change)
        download_layout.addWidget(self.download_users_csv_btn)
        download_info_label = QLabel(f"CSV will be saved to:\n{BULK_CHANGE_DIR}")
        download_info_label.setWordWrap(True)
        download_layout.addWidget(download_info_label)
        csv_workflow_layout.addWidget(download_group)
        apply_domain_group = QGroupBox("Step 1.2: Select New Domain and Apply to Downloaded CSV")
        apply_domain_layout = QHBoxLayout(apply_domain_group)
        domain_list_layout = QVBoxLayout()
        self.retrieve_domains_bulk_btn = QPushButton("🔍 Retrieve Available Domains")
        self.retrieve_domains_bulk_btn.setToolTip("Fetch verified domains for the authenticated account.")
        self.retrieve_domains_bulk_btn.clicked.connect(self.retrieve_domains_for_bulk_change)
        domain_list_layout.addWidget(self.retrieve_domains_bulk_btn)
        self.bulk_change_domain_list = QListWidget()
        self.bulk_change_domain_list.setToolTip("Select the target domain to apply to the CSV.")
        # self.bulk_change_domain_list.setMaximumHeight(120) # MODIFICATION: Removed max height
        domain_list_layout.addWidget(self.bulk_change_domain_list)
        apply_domain_layout.addLayout(domain_list_layout, 2)
        apply_button_layout = QVBoxLayout()
        self.apply_domain_to_csv_btn = QPushButton("➡️ Apply Selected\nDomain to CSV")
        self.apply_domain_to_csv_btn.setToolTip("Modifies the 'New Email' column in the *last downloaded CSV*\nusing the domain selected from the list (excludes admin@...).")
        self.apply_domain_to_csv_btn.clicked.connect(self.apply_selected_domain_to_csv)
        apply_button_layout.addWidget(self.apply_domain_to_csv_btn)
        apply_button_layout.addStretch()
        apply_domain_layout.addLayout(apply_button_layout, 1)
        csv_workflow_layout.addWidget(apply_domain_group)
        process_group = QGroupBox("Step 1.3: Process Domain Changes from Modified CSV")
        process_layout = QVBoxLayout(process_group)
        upload_layout = QHBoxLayout()
        self.bulk_change_csv_entry = QLineEdit()
        self.bulk_change_csv_entry.setPlaceholderText("CSV file path will appear here after download/apply, or browse manually...")
        self.bulk_change_csv_entry.setReadOnly(True)
        upload_layout.addWidget(self.bulk_change_csv_entry, 1)
        self.browse_bulk_change_csv_btn = QPushButton("📁 Browse Manually...")
        self.browse_bulk_change_csv_btn.setToolTip("Manually select a CSV file if you didn't use Step 2.")
        self.browse_bulk_change_csv_btn.clicked.connect(self.browse_bulk_change_csv)
        upload_layout.addWidget(self.browse_bulk_change_csv_btn)
        process_layout.addLayout(upload_layout)
        self.process_bulk_change_btn = QPushButton("⚙️ Process Domain Changes from CSV")
        self.process_bulk_change_btn.setToolTip("Reads the selected CSV and updates user emails based on 'Current Email' and 'New Email' columns.")
        self.process_bulk_change_btn.clicked.connect(self.process_bulk_domain_change)
        process_layout.addWidget(self.process_bulk_change_btn)
        csv_workflow_layout.addWidget(process_group)
        main_layout.addWidget(csv_workflow_group)

        # --- Workflow 2: Change Domain for All Users (Non-CSV) ---
        all_users_workflow_group = QGroupBox("Workflow 2: Change Domain for All Users (Non-CSV, Excludes Admin)")
        all_users_layout = QVBoxLayout(all_users_workflow_group)
        inputs_layout = QGridLayout()
        inputs_layout.addWidget(QLabel("Current Domain Suffix:"), 0, 0)
        self.all_users_current_domain_entry = QLineEdit()
        self.all_users_current_domain_entry.setPlaceholderText("e.g., old-domain.com")
        inputs_layout.addWidget(self.all_users_current_domain_entry, 0, 1)
        inputs_layout.addWidget(QLabel("New Domain Suffix:"), 1, 0)
        self.all_users_new_domain_entry = QLineEdit()
        self.all_users_new_domain_entry.setPlaceholderText("e.g., new-domain.com")
        inputs_layout.addWidget(self.all_users_new_domain_entry, 1, 1)
        all_users_layout.addLayout(inputs_layout)
        self.change_all_users_domain_btn = QPushButton("🚀 Change Domain for ALL Matching Users (Non-Admin)")
        self.change_all_users_domain_btn.setToolTip("Fetches all users via API and updates the domain for those matching the 'Current Domain'\n(excluding users starting with 'admin@'). Uses Batch API for speed.")
        self.change_all_users_domain_btn.clicked.connect(self.change_domain_for_all_users)
        all_users_layout.addWidget(self.change_all_users_domain_btn)
        main_layout.addWidget(all_users_workflow_group)

        # --- Results Log Group ---
        results_group = QGroupBox("Results Log (Covers Both Workflows)")
        results_layout = QVBoxLayout(results_group)
        self.bulk_change_log_text = QPlainTextEdit()
        self.bulk_change_log_text.setReadOnly(True)
        self.bulk_change_log_text.setPlaceholderText("Processing results will appear here...")
        results_layout.addWidget(self.bulk_change_log_text, 1)
        self.clear_bulk_change_log_btn = QPushButton("🧹 Clear Log")
        self.clear_bulk_change_log_btn.clicked.connect(lambda: self.bulk_change_log_text.clear())
        results_layout.addWidget(self.clear_bulk_change_log_btn)
        main_layout.addWidget(results_group)

        main_layout.addStretch()

        # --- Scroll Area ---
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(container_widget)
        return scroll_area



    # --- Methods for Bulk Domain Change Tab ---

    def download_users_for_bulk_change(self):
        """Fetches all users and saves them to a CSV for bulk editing."""
        if not self.google_api.service:
            QMessageBox.warning(self, "Not Authenticated", "Please authenticate an account first.")
            return
        if not self.google_api.current_account_name:
             QMessageBox.warning(self, "Authentication Error", "Cannot determine the current account. Please re-authenticate.")
             self.last_downloaded_bulk_csv_path = None # Reset path on error
             return


        self.log_message("Starting user download for bulk change...", self.bulk_change_log_text)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        self.last_downloaded_bulk_csv_path = None # Reset path at start of download
        # Clear the file path entry from previous runs
        self.bulk_change_csv_entry.clear()
        # Clear the domain list as well, as it corresponds to the previous account/download
        self.bulk_change_domain_list.clear()

        try:
            users_data = []
            page_token = None
            total_users_fetched = 0
            while True:
                results = self.google_api.service.users().list(
                    customer='my_customer',
                    orderBy='email',
                    maxResults=500, # Max per page
                    projection='full', # Need names
                    fields='nextPageToken,users(primaryEmail,name(givenName,familyName),suspended)', # Specify fields
                    pageToken=page_token
                ).execute()

                current_page_users = results.get('users', [])
                total_users_fetched += len(current_page_users)
                self.log_message(f"Fetched page with {len(current_page_users)} users (Total: {total_users_fetched})...", self.bulk_change_log_text)
                QApplication.processEvents() # Keep UI responsive during fetch

                for user in current_page_users:
                    users_data.append({
                        'Current Email': user.get('primaryEmail', 'N/A'),
                        'New Email': user.get('primaryEmail', 'N/A'), # Initialize New Email same as Current
                        'First Name': user.get('name', {}).get('givenName', ''),
                        'Last Name': user.get('name', {}).get('familyName', ''),
                        'Suspended': user.get('suspended', False)
                    })

                page_token = results.get('nextPageToken')
                if not page_token:
                    break

            if not users_data:
                self.log_message("No users found for the authenticated account.", self.bulk_change_log_text)
                QMessageBox.information(self, "No Users", "No users were found for the current account.")
                return

            df = pd.DataFrame(users_data)

            # Ensure the target directory exists
            ensure_bulk_change_dir()

            # Create a unique filename
            account_name_safe = re.sub(r'[^\w\-.]', '_', self.google_api.current_account_name) # Sanitize account name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"Users_{account_name_safe}_{timestamp}.csv"
            save_path = os.path.join(BULK_CHANGE_DIR, filename)

            # --- STORE THE PATH ---
            self.last_downloaded_bulk_csv_path = save_path
            # --- Automatically populate the entry field ---
            self.bulk_change_csv_entry.setText(save_path)

            # Save to CSV
            df.to_csv(save_path, index=False, encoding='utf-8')

            success_msg = f"Successfully downloaded {len(users_data)} users to:\n{save_path}\nReady for Step 2 (Select Domain)."
            self.log_message(success_msg, self.bulk_change_log_text)
            QMessageBox.information(self, "Download Complete", success_msg)

        except HttpError as http_err:
             error_msg = f"API Error downloading users: {http_err}"
             logging.error(error_msg)
             self.log_message(f"ERROR: {error_msg}", self.bulk_change_log_text)
             QMessageBox.critical(self, "API Error", error_msg)
             self.last_downloaded_bulk_csv_path = None # Reset path on error
        except Exception as e:
            error_msg = f"An unexpected error occurred during user download: {e}"
            logging.error(error_msg, exc_info=True)
            self.log_message(f"ERROR: {error_msg}", self.bulk_change_log_text)
            QMessageBox.critical(self, "Download Error", error_msg)
            self.last_downloaded_bulk_csv_path = None # Reset path on error
        finally:
            QApplication.restoreOverrideCursor()

# In the MainWindow class:

    def retrieve_domains_for_bulk_change(self):
        """Retrieves verified domains and populates the list in the Bulk Change tab with colors."""
        if not self.google_api.service:
            QMessageBox.warning(self, "Not Authenticated", "Please authenticate an account first.")
            return

        self.log_message("Retrieving domains for selection...", self.bulk_change_log_text)
        self.bulk_change_domain_list.clear() # Clear previous list
        QApplication.setOverrideCursor(Qt.WaitCursor)

        try:
            # domains_info is now: List[Tuple[parent_info_dict, List[sub_info_dict]]]
            grouped_domains_list = self.google_api.get_subdomains() 

            if not grouped_domains_list:
                 self.log_message("No verified domains found for this account.", self.bulk_change_log_text)
                 QMessageBox.information(self, "No Domains", "No verified domains are associated with this account.")
                 return

            # Define colors (adjust hex codes as needed for your theme)
            used_color = QColor("#FF5252") if self.dark_theme_enabled else QColor(Qt.red)        # Reddish
            unused_color = QColor("#4CAF50") if self.dark_theme_enabled else QColor(Qt.darkGreen) # Greenish

            domain_count = 0
            # Flatten the structure for display in the list
            all_displayable_domains_info = []
            for parent_info, sub_list in grouped_domains_list:
                all_displayable_domains_info.append(parent_info)
                all_displayable_domains_info.extend(sub_list)
            
            # Sort them by name for consistent display, or keep API order from flat_verified_domains_ordered_info in get_subdomains
            # For now, let's keep the order they came in via flat_verified_domains_ordered_info logic in get_subdomains.
            # If a specific sort (e.g. alphabetical) is needed here, apply it to `all_displayable_domains_info`.


            for info in all_displayable_domains_info: # Iterate through the flattened list of info dicts
                domain_count += 1
                item = QListWidgetItem(info['domain_name']) # Create item with domain name text
                item.setToolTip(f"Active Users: {info['count_active']}, Total Users: {info['count_total']}")

                # Set color based on active usage
                if info['used_active']:
                    item.setForeground(used_color)
                else:
                    item.setForeground(unused_color)

                self.bulk_change_domain_list.addItem(item) # Add the styled item

            self.log_message(f"Successfully retrieved and displayed {domain_count} domains with usage status.", self.bulk_change_log_text)

        except Exception as e:
             # Error handling done within get_subdomains, just log here
             error_msg = f"Failed to retrieve/display domains: {e}"
             logging.error(error_msg, exc_info=True)
             self.log_message(f"ERROR retrieving domains: {e}", self.bulk_change_log_text)
             QMessageBox.critical(self, "Domain Retrieval Error", error_msg)
        finally:
             QApplication.restoreOverrideCursor()



    def apply_selected_domain_to_csv(self):
        """Modifies the last downloaded CSV file with the selected domain."""
        # 1. Check if a CSV was downloaded in this session
        if not self.last_downloaded_bulk_csv_path or not os.path.exists(self.last_downloaded_bulk_csv_path):
            QMessageBox.warning(self, "CSV Not Found", "Please download the user list using 'Step 1: Download All Users' first.")
            return

        # 2. Check if a domain is selected
        selected_items = self.bulk_change_domain_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Domain Selected", "Please select a target domain from the list.")
            return
        selected_domain = selected_items[0].text().strip() # Get the first selected domain

        self.log_message(f"Attempting to apply domain '{selected_domain}' to CSV: {self.last_downloaded_bulk_csv_path}", self.bulk_change_log_text)
        QApplication.setOverrideCursor(Qt.WaitCursor)

        modified_count = 0
        admin_skipped_count = 0
        error_occurred = False

        try:
            # 3. Read the CSV
            df = pd.read_csv(self.last_downloaded_bulk_csv_path, dtype=str).fillna('')

            if 'Current Email' not in df.columns or 'New Email' not in df.columns:
                 raise ValueError("CSV is missing 'Current Email' or 'New Email' columns.")

            # 4. Iterate and modify (using .loc for direct modification is efficient)
            for index in df.index:
                current_email = df.loc[index, 'Current Email'].strip()

                if not current_email or '@' not in current_email:
                     self.log_message(f"  Skipping row {index+2}: Invalid Current Email '{current_email}'", self.bulk_change_log_text)
                     continue # Skip rows with invalid current emails

                # --- Exclude admin ---
                if current_email.lower().startswith('admin@'):
                    self.log_message(f"  Skipping admin user: {current_email}", self.bulk_change_log_text)
                    admin_skipped_count += 1
                    # Ensure admin's New Email remains unchanged (set it back to Current just in case)
                    df.loc[index, 'New Email'] = current_email
                    continue

                # Extract alias and construct new email
                try:
                    alias = current_email.split('@')[0]
                    new_email = f"{alias}@{selected_domain}"

                    # Only count as modified if the email actually changes
                    if df.loc[index, 'New Email'] != new_email:
                        df.loc[index, 'New Email'] = new_email
                        modified_count += 1
                except Exception as e_row:
                     self.log_message(f"  Error processing row {index+2} for '{current_email}': {e_row}", self.bulk_change_log_text)
                     # Continue to next row, maybe mark as error?

            # 5. Save the modified DataFrame back to the *same file*
            df.to_csv(self.last_downloaded_bulk_csv_path, index=False, encoding='utf-8')

            # Update the entry field again (redundant if already set, but safe)
            self.bulk_change_csv_entry.setText(self.last_downloaded_bulk_csv_path)

            success_msg = (f"Successfully modified CSV: {self.last_downloaded_bulk_csv_path}\n"
                           f"- Applied domain: '{selected_domain}'\n"
                           f"- Emails updated: {modified_count}\n"
                           f"- Admin users skipped: {admin_skipped_count}\n\n"
                           f"Ready for 'Step 3: Process Domain Changes'.")
            self.log_message(success_msg, self.bulk_change_log_text)
            QMessageBox.information(self, "CSV Updated", success_msg)

        except (FileNotFoundError, ValueError, pd.errors.EmptyDataError) as e:
             error_msg = f"Error reading or processing CSV file: {e}"
             self.log_message(f"ERROR: {error_msg}", self.bulk_change_log_text)
             QMessageBox.critical(self, "CSV Error", error_msg)
             error_occurred = True
        except Exception as e:
            error_msg = f"An unexpected error occurred while applying domain to CSV: {e}"
            logging.error(error_msg, exc_info=True)
            self.log_message(f"ERROR: {error_msg}", self.bulk_change_log_text)
            QMessageBox.critical(self, "Processing Error", error_msg)
            error_occurred = True
        finally:
            QApplication.restoreOverrideCursor()

    def browse_bulk_change_csv(self):
        """Opens a file dialog to select the modified CSV file."""
        # Start browsing in the directory where files are downloaded, if it exists
        start_dir = BULK_CHANGE_DIR if os.path.exists(BULK_CHANGE_DIR) else os.path.expanduser("~")
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Modified CSV File", start_dir, "CSV files (*.csv)")
        if file_path:
            self.bulk_change_csv_entry.setText(file_path)
            self.log_message(f"Selected file for processing: {file_path}", self.bulk_change_log_text)


    def process_bulk_domain_change(self):
        """Reads the selected CSV and processes the email updates using Batch API."""
        csv_path = self.bulk_change_csv_entry.text()
        if not csv_path or not os.path.exists(csv_path):
            QMessageBox.warning(self, "No File Selected", "Please browse for and select the modified CSV file first.")
            return

        if not self.google_api.service:
            QMessageBox.warning(self, "Not Authenticated", "Please authenticate an account before processing changes.")
            return

        self.log_message(f"\n--- Starting Bulk Domain Change Process (Batch Mode) ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ---", self.bulk_change_log_text)
        self.log_message(f"Reading data from: {csv_path}", self.bulk_change_log_text)
        QApplication.setOverrideCursor(Qt.WaitCursor)

        # --- Initialize counters ---
        self.initialize_batch_counters()
        skipped_count = 0
        total_rows = 0
        requests_in_current_batch = 0
        requests_queued_total = 0
        BATCH_SIZE = 100 # Number of requests per batch (adjust as needed, 50-100 is often safe)

        try:
            df = pd.read_csv(csv_path, dtype=str).fillna('') # Read all as string
            total_rows = len(df)
            self.log_message(f"Found {total_rows} rows in CSV. Starting batch preparation...", self.bulk_change_log_text)

            required_cols = ['Current Email', 'New Email']
            if not all(col in df.columns for col in required_cols):
                raise ValueError("Missing required columns in CSV: 'Current Email' or 'New Email'")

            # --- Initialize Batch ---
            batch = self.google_api.service.new_batch_http_request(callback=self.batch_callback)

            # --- Iterate through CSV and build batches ---
            for index, row in df.iterrows():
                current_email = str(row['Current Email']).strip()
                new_email = str(row['New Email']).strip()

                # Basic validation & check if change needed
                if not current_email or '@' not in current_email:
                    # self.log_message(f"Skipping row {index+2}: Invalid 'Current Email'.", self.bulk_change_log_text)
                    skipped_count += 1
                    continue
                if not new_email or '@' not in new_email:
                    # self.log_message(f"Skipping row {index+2}: Invalid 'New Email' for {current_email}.", self.bulk_change_log_text)
                    skipped_count += 1
                    continue
                if current_email.lower() == new_email.lower():
                    # No change needed
                    skipped_count += 1
                    continue

                # Prepare update payload
                update_payload = {'primaryEmail': new_email}
                requests_queued_total += 1

                # Add request to the batch
                # Use current_email as request_id for easy identification in callback
                batch.add(
                    self.google_api.service.users().update(userKey=current_email, body=update_payload),
                    request_id=current_email
                )
                requests_in_current_batch += 1

                # --- Execute batch if size limit reached ---
                if requests_in_current_batch >= BATCH_SIZE:
                    self.log_message(f"Executing batch of {requests_in_current_batch} requests (Total queued: {requests_queued_total})...", self.bulk_change_log_text)
                    QApplication.processEvents() # Update UI before potentially long batch execution
                    try:
                        batch.execute()
                    except Exception as batch_exec_err:
                         # Log error for the whole batch execution, individual errors handled by callback
                         self.log_message(f"ERROR executing batch: {batch_exec_err}", self.bulk_change_log_text)
                         logging.error(f"Batch execution error: {batch_exec_err}", exc_info=True)
                         # Decide whether to stop or continue? Let's try continuing.
                         # We might lose tracking of which specific requests failed here if the whole execute crashes.

                    # Reset for next batch
                    batch = self.google_api.service.new_batch_http_request(callback=self.batch_callback)
                    requests_in_current_batch = 0
                    # Short pause might help with rate limits between batches
                    time.sleep(0.5)


            # --- Execute any remaining requests in the last batch ---
            if requests_in_current_batch > 0:
                self.log_message(f"Executing final batch of {requests_in_current_batch} requests (Total queued: {requests_queued_total})...", self.bulk_change_log_text)
                QApplication.processEvents()
                try:
                    batch.execute()
                except Exception as batch_exec_err:
                     self.log_message(f"ERROR executing final batch: {batch_exec_err}", self.bulk_change_log_text)
                     logging.error(f"Final Batch execution error: {batch_exec_err}", exc_info=True)

            self.log_message(f"All {requests_queued_total} update requests queued and batches executed. Waiting for callbacks...", self.bulk_change_log_text)
            # Note: Batch execution might be asynchronous in some libraries/contexts.
            # Here, `batch.execute()` is typically blocking until completion,
            # but callbacks might arrive slightly after. A short sleep might ensure logs finalize.
            time.sleep(2)

            # --- Final Summary (using counters updated by callback) ---
            summary_msg = (
                f"\n--- Bulk Domain Change (Batch) Finished ---\n"
                f"Total Rows in CSV: {total_rows}\n"
                f"Requests Queued for Update: {requests_queued_total}\n"
                f"Successfully Updated (via callbacks): {self.batch_success_count}\n"
                f"Failed Updates (via callbacks): {self.batch_fail_count}\n"
                f"Skipped (No Change/Invalid Data): {skipped_count}"
            )
            # Sanity check if callback count matches queued requests
            if self.batch_total_processed_in_callbacks != requests_queued_total:
                 summary_msg += f"\n\nWarning: Callback count ({self.batch_total_processed_in_callbacks}) doesn't match queued requests ({requests_queued_total}). Some results might be missing."

            self.log_message(summary_msg, self.bulk_change_log_text)
            QMessageBox.information(self, "Batch Process Complete", summary_msg.replace("\n---", "\n").strip())


        except pd.errors.EmptyDataError:
             error_msg = "The selected CSV file is empty."
             self.log_message(f"ERROR: {error_msg}", self.bulk_change_log_text)
             QMessageBox.critical(self, "CSV Error", error_msg)
        except FileNotFoundError:
            error_msg = f"The file was not found: {csv_path}"
            self.log_message(f"ERROR: {error_msg}", self.bulk_change_log_text)
            QMessageBox.critical(self, "File Error", error_msg)
        except ValueError as ve: # Catch column errors
            error_msg = f"CSV Data Error: {ve}"
            self.log_message(f"ERROR: {error_msg}", self.bulk_change_log_text)
            QMessageBox.critical(self, "CSV Error", error_msg)
        except Exception as e:
            error_msg = f"An unexpected error occurred during batch processing setup or execution: {e}"
            logging.error(error_msg, exc_info=True)
            self.log_message(f"FATAL ERROR: {error_msg}", self.bulk_change_log_text)
            QMessageBox.critical(self, "Processing Error", error_msg)
        finally:
            QApplication.restoreOverrideCursor()



    # ------------------------------------------------
    # Selenium Login and OTP Handling
    # ------------------------------------------------
    def login_account(self, email, password):
        if not self.driver:
            self.log_message(f"ERROR: WebDriver not initialized. Cannot login {email}.")
            QMessageBox.critical(self, "Driver Error", "WebDriver is not running. Please restart the application or check driver setup.")
            return False # Indicate failure

        self.log_message(f"Attempting login for: {email}")
        try:
            self.driver.get("https://accounts.google.com/ServiceLogin")

            # --- Email Input ---
            try:
                email_input = WebDriverWait(self.driver, 15).until(
                    EC.visibility_of_element_located((By.ID, "identifierId"))
                )
                email_input.clear()
                # Simulate typing more naturally
                for char in email:
                    email_input.send_keys(char)
                    time.sleep(random.uniform(0.05, 0.15)) # Small random delay
                email_input.send_keys(Keys.ENTER)
                self.log_message(f"Entered email: {email}")
                time.sleep(random.uniform(1.5, 2.5)) # Wait after entering email
            except TimeoutException:
                 self.log_message(f"ERROR: Timeout waiting for email input field for {email}.")
                 # Check for common issues like CAPTCHA or different page structure
                 if "consent.google.com" in self.driver.current_url:
                      self.log_message("Consent screen detected. Manual intervention might be required.")
                 elif self.driver.find_elements(By.ID, "captcha-form"):
                      self.log_message("CAPTCHA detected. Cannot proceed automatically.")
                 else:
                      self.log_message(f"Current URL: {self.driver.current_url}")
                      # self.driver.save_screenshot(f"error_email_input_{email}.png") # Save screenshot for debugging
                 return False


            # --- Password Input ---
            try:
                # Wait for password field visibility (name can be 'Passwd' or 'password')
                password_input = WebDriverWait(self.driver, 15).until(
                     EC.visibility_of_element_located((By.XPATH, '//input[@type="password"][@name="Passwd" or @name="password"]'))
                )
                password_input.clear()
                 # Simulate typing
                for char in password:
                    password_input.send_keys(char)
                    time.sleep(random.uniform(0.05, 0.15))
                password_input.send_keys(Keys.ENTER)
                self.log_message("Entered password.")
                time.sleep(random.uniform(2, 4)) # Wait longer after password submission
            except TimeoutException:
                 self.log_message(f"ERROR: Timeout waiting for password input field for {email}.")
                 self.log_message(f"Current URL: {self.driver.current_url}")
                 # self.driver.save_screenshot(f"error_password_input_{email}.png")
                 # Check if login failed (e.g., wrong password message)
                 if self.driver.find_elements(By.XPATH, "//*[contains(text(), 'Wrong password')]"):
                     self.log_message("Wrong password detected.")
                 return False

            # --- Handle Post-Login Challenges (2FA/OTP, Recovery Prompts) ---
            challenge_handled = False
            # Check for TOTP challenge specifically first
            if "/challenge/totp" in self.driver.current_url or self.driver.find_elements(By.ID, "totpPin"):
                self.log_message("TOTP (Authenticator App) challenge detected.")
                if self.handle_otp_challenge(email):
                    challenge_handled = True
                    time.sleep(random.uniform(2, 3)) # Wait after OTP entry
                else:
                     self.log_message(f"ERROR: Failed to handle OTP challenge for {email}.")
                     return False # Stop if OTP fails
            # Check for other common challenges (e.g., phone verification, recovery prompts)
            elif "/challenge/" in self.driver.current_url:
                 # Try to identify the type of challenge if possible
                 if self.driver.find_elements(By.XPATH, "//*[contains(text(), 'Verify it')]") or self.driver.find_elements(By.XPATH, "//*[contains(text(), 'Get a verification code')]"):
                     self.log_message("Phone verification or other 2FA challenge detected. Automatic handling not implemented for this type.")
                     # You might try clicking common buttons like "Try another way" if applicable,
                     # but this gets complex quickly.
                     # For now, log and fail.
                     # self.driver.save_screenshot(f"challenge_unhandled_{email}.png")
                     return False
                 elif self.driver.find_elements(By.XPATH, "//*[contains(text(), 'Confirm your recovery email')]") or self.driver.find_elements(By.XPATH, "//*[contains(text(), 'Confirm your recovery phone')]"):
                      self.log_message("Recovery confirmation prompt detected. Trying to skip...")
                      # Try clicking 'Confirm' or 'Skip'/'Not now' if available
                      try:
                           # Look for buttons like "Confirm", "Done", "Not now"
                           confirm_button = self.driver.find_element(By.XPATH, "//button[.//span[contains(text(), 'Confirm')] or .//span[contains(text(), 'Done')] or .//span[contains(text(), 'Not now')]]")
                           confirm_button.click()
                           self.log_message("Clicked a confirmation/skip button for recovery prompt.")
                           challenge_handled = True
                           time.sleep(random.uniform(1.5, 2.5))
                      except NoSuchElementException:
                           self.log_message("Could not find a standard button to skip recovery prompt.")
                           # self.driver.save_screenshot(f"challenge_recovery_{email}.png")
                           # Decide whether to proceed or fail - Proceeding might be okay.
                           challenge_handled = True # Assume we can proceed for now
                 else:
                      self.log_message(f"Unknown challenge detected at URL: {self.driver.current_url}. Manual intervention likely required.")
                      # self.driver.save_screenshot(f"challenge_unknown_{email}.png")
                      return False # Fail on unknown challenges

            # --- Verification: Check if login was successful ---
            # A reliable check is often to navigate to a known logged-in page like myaccount.google.com
            # or the target page (admin console).
            time.sleep(1) # Short pause before verification nav
            self.driver.get("https://admin.google.com/") # Navigate to admin console home
            time.sleep(random.uniform(2, 4)) # Wait for admin console to load

            current_url = self.driver.current_url
            if "admin.google.com/AdminHome" in current_url:
                self.log_message(f"SUCCESS: Login confirmed for {email} (Admin Console loaded).")
                return True
            elif "myaccount.google.com" in current_url: # Fallback check
                 self.log_message(f"SUCCESS: Login possibly confirmed for {email} (My Account page loaded).")
                 return True
            else:
                # If still on a login/challenge page, it failed.
                self.log_message(f"ERROR: Login verification failed for {email}. Final URL: {current_url}")
                # Check for common error messages again
                if self.driver.find_elements(By.XPATH, "//*[contains(text(), 'couldn't sign you in')]"):
                     self.log_message("Google reported sign-in failure.")
                # self.driver.save_screenshot(f"error_login_verify_{email}.png")
                return False

        except TimeoutException as te:
            self.log_message(f"ERROR: Timeout during login process for {email}: {te}")
            # self.driver.save_screenshot(f"error_timeout_{email}.png")
            return False
        except WebDriverException as wde:
             self.log_message(f"ERROR: WebDriverException during login for {email}: {wde}. Driver session might be invalid.")
             # Consider quitting the driver here if it's unstable
             # self.close_driver()
             return False
        except Exception as ex:
            self.log_message(f"ERROR: Unexpected error during login for {email}: {ex}")
            logging.error(f"Login error details for {email}:", exc_info=True) # Log stack trace
            # self.driver.save_screenshot(f"error_unexpected_{email}.png")
            return False

    # ------------------------------------------------
    # OTP Handling (Refined)
    # ------------------------------------------------
    def handle_otp_challenge(self, email):
        """Finds secret key, generates code, enters it."""
        secret_key = self.find_secret_key_for_email(email)
        if not secret_key:
            self.log_message(f"ERROR: No secret key file found for {email} (expected <email>_authenticator_secret_key.txt).")
            return False

        totp_code = self.generate_otp_code(secret_key)
        if not totp_code:
            self.log_message(f"ERROR: Could not generate OTP code for {email}. Check secret key format.")
            return False

        self.log_message(f"Generated OTP: {totp_code} for {email}")

        try:
            # Locate the OTP input field (often has type='tel' or id='totpPin')
            otp_input = WebDriverWait(self.driver, 15).until(
                EC.visibility_of_element_located((By.XPATH, '//input[@type="tel" or @id="totpPin"]'))
            )
            otp_input.clear()
            # Simulate typing OTP
            for digit in totp_code:
                 otp_input.send_keys(digit)
                 time.sleep(random.uniform(0.05, 0.15))

            # Find and click the 'Next' or 'Verify' button
            # Common texts: Next, Verify, Done
            next_button = WebDriverWait(self.driver, 10).until(
                EC.element_to_be_clickable((By.XPATH, "//button[.//span[contains(text(), 'Next')] or .//span[contains(text(), 'Verify')] or .//span[contains(text(), 'Done')]]"))
            )
            next_button.click()
            self.log_message(f"Entered OTP and clicked Next/Verify for {email}.")
            return True
        except TimeoutException:
            self.log_message(f"ERROR: Timeout finding OTP input field or Next button for {email}.")
            # Check for error messages like "Wrong code"
            if self.driver.find_elements(By.XPATH, "//*[contains(text(), 'Wrong code')]"):
                 self.log_message("Google reported 'Wrong code'. Check system time and secret key.")
            # self.driver.save_screenshot(f"error_otp_timeout_{email}.png")
            return False
        except Exception as e:
            self.log_message(f"ERROR: Unexpected error entering OTP for {email}: {e}")
            logging.error(f"OTP entry error details for {email}:", exc_info=True)
            # self.driver.save_screenshot(f"error_otp_unexpected_{email}.png")
            return False

    def generate_otp_code(self, secret_key):
        """Generates a 6-digit TOTP code."""
        try:
            # Sanitize: Remove spaces and ensure uppercase base32 characters
            sanitized_key = ''.join(filter(lambda c: c.upper() in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", secret_key.upper()))
            if not sanitized_key or len(sanitized_key) < 16: # Basic length check for typical keys
                self.log_message(f"Warning: Sanitized secret key '{sanitized_key}' seems short or invalid.")
                # Allow proceeding, but log warning

            totp = pyotp.TOTP(sanitized_key)
            return totp.now()
        except Exception as e:
            self.log_message(f"ERROR: Could not generate OTP code from key '{secret_key[:4]}...': {e}")
            logging.error(f"Error generating OTP:", exc_info=True)
            return None

    def find_secret_key_for_email(self, email):
        """
        Looks for <email>_authenticator_secret_key.txt locally first,
        then attempts to download from SFTP server's account-specific folder.
        """
        local_dir = os.getcwd()
        filename = f"{email}_authenticator_secret_key.txt"
        local_path = os.path.join(local_dir, filename)

        # 1. Check locally first
        if os.path.exists(local_path):
            self.log_message(f"Found local secret key file: {local_path}")
            try:
                with open(local_path, "r") as f:
                    return f.read().strip()
            except Exception as e:
                 self.log_message(f"ERROR: Could not read local secret key file {local_path}: {e}")
                 return None

        # 2. If not found locally, try SFTP
        self.log_message(f"Local secret key file not found. Trying SFTP download for {email}...")
        # Determine potential remote paths (adjust logic if needed)
        remote_path1 = f"/home/Google_Api/{email}/{filename}"
        remote_path2 = f"/home/brightmindscampus/{email}/{filename}"
        sftp = None # Initialize sftp variable

        try:
            sftp = self.sftp_connect()
            if not sftp:
                self.log_message("ERROR: SFTP connection failed, cannot download secret key.")
                return None

            # Try downloading from the first path
            try:
                sftp.get(remote_path1.replace('\\', '/'), local_path)
                self.log_message(f"Downloaded secret key from {remote_path1}")
                with open(local_path, "r") as f:
                    return f.read().strip()
            except FileNotFoundError:
                 self.log_message(f"Secret key not found at {remote_path1}. Trying alternative path...")
                 # Try downloading from the second path
                 try:
                     sftp.get(remote_path2.replace('\\', '/'), local_path)
                     self.log_message(f"Downloaded secret key from {remote_path2}")
                     with open(local_path, "r") as f:
                         return f.read().strip()
                 except FileNotFoundError:
                     self.log_message(f"Secret key not found at {remote_path2} either.")
                     return None
                 except Exception as e_sftp2:
                      self.log_message(f"ERROR: Failed to download/read secret key from {remote_path2}: {e_sftp2}")
                      return None
            except Exception as e_sftp1:
                 self.log_message(f"ERROR: Failed to download/read secret key from {remote_path1}: {e_sftp1}")
                 return None

        except Exception as e_conn:
             self.log_message(f"ERROR: SFTP operation failed: {e_conn}")
             return None
        finally:
            if sftp:
                 try:
                     sftp.close()
                 except Exception as e_close:
                      logging.warning(f"Error closing SFTP connection: {e_close}")
            # Clean up downloaded file if we failed to read it or it wasn't found remotely
            # (Optional: keep it if downloaded successfully but read failed)
            # if not secret_key_content and os.path.exists(local_path):
            #     try: os.remove(local_path)
            #     except: pass

        return None # Return None if not found anywhere


    def login_from_file(self):
        """
        Downloads login.txt for the selected account, then iterates through
        username:password pairs, logging into each using Selenium.
        """
        selected_account_item = self.accounts_listbox.currentItem()
        if not selected_account_item:
            QMessageBox.warning(self, "No Account Selected", "Please select an account from the list first.")
            return

        account_name = selected_account_item.text().strip()
        if not account_name:
            QMessageBox.warning(self, "Invalid Account", "The selected account name is empty/invalid.")
            return

        self.log_message(f"--- Starting Browser Login Process for Account: {account_name} ---")

        # Define remote paths for login.txt
        remote_file_primary = f"/home/Google_Api/{account_name}/login.txt"
        remote_file_secondary = f"/home/brightmindscampus/{account_name}/login.txt"
        local_temp_file = os.path.join(os.getcwd(), f"{account_name}_login_temp.txt")

        # --- Download login.txt ---
        sftp = None
        login_txt_downloaded = False
        try:
            sftp = self.sftp_connect()
            if not sftp: return # Error message shown by sftp_connect

            try:
                sftp.get(remote_file_primary.replace('\\', '/'), local_temp_file)
                self.log_message(f"Downloaded login file from: {remote_file_primary}")
                login_txt_downloaded = True
            except FileNotFoundError:
                self.log_message(f"login.txt not found at primary location. Trying secondary...")
                try:
                     sftp.get(remote_file_secondary.replace('\\', '/'), local_temp_file)
                     self.log_message(f"Downloaded login file from: {remote_file_secondary}")
                     login_txt_downloaded = True
                except FileNotFoundError:
                     error_msg = f"Could not find login.txt on the server for account '{account_name}' in either primary or secondary location."
                     self.log_message(f"ERROR: {error_msg}")
                     QMessageBox.critical(self, "File Not Found", error_msg)
                     return # Stop if file not found
                except Exception as e_sftp2:
                      error_msg = f"Error downloading login.txt from secondary location: {e_sftp2}"
                      self.log_message(f"ERROR: {error_msg}")
                      QMessageBox.critical(self, "SFTP Error", error_msg)
                      return
            except Exception as e_sftp1:
                 error_msg = f"Error downloading login.txt from primary location: {e_sftp1}"
                 self.log_message(f"ERROR: {error_msg}")
                 QMessageBox.critical(self, "SFTP Error", error_msg)
                 return

        except Exception as e_conn:
             error_msg = f"SFTP connection/operation failed: {e_conn}"
             self.log_message(f"ERROR: {error_msg}")
             QMessageBox.critical(self, "SFTP Error", error_msg)
             return # Stop if SFTP fails
        finally:
            if sftp:
                 try: sftp.close()
                 except: pass

        if not login_txt_downloaded: return # Should have returned earlier, but double-check

        # --- Read credentials from downloaded file ---
        credentials = []
        try:
            with open(local_temp_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for i, line in enumerate(lines):
                line = line.strip()
                if not line or line.startswith('#'): # Skip empty lines and comments
                    continue
                if ":" not in line:
                    self.log_message(f"Warning: Skipping invalid line {i+1} in login.txt (missing ':'): {line}")
                    continue
                username, password = line.split(":", 1)
                username = username.strip()
                password = password.strip()
                if not username or not password:
                     self.log_message(f"Warning: Skipping invalid line {i+1} in login.txt (empty user/pass): {line}")
                     continue
                credentials.append({'user': username, 'pass': password})
            self.log_message(f"Read {len(credentials)} credential pairs from login.txt.")
        except Exception as e_read:
            self.log_message(f"ERROR: Failed to read or parse {local_temp_file}: {e_read}")
            QMessageBox.critical(self, "File Read Error", f"Error reading login file: {e_read}")
            # Clean up local file even on error
            if os.path.exists(local_temp_file):
                try: os.remove(local_temp_file)
                except: pass
            return

        # --- Initialize WebDriver ---
        # Init driver outside the loop, but ensure it's valid before each login attempt
        if not self.driver:
            self.init_driver(headless=False) # Start non-headless for login process
        if not self.driver:
            self.log_message("ERROR: WebDriver initialization failed. Cannot proceed with logins.")
            # Clean up local file
            if os.path.exists(local_temp_file):
                try: os.remove(local_temp_file)
                except: pass
            return

        # --- Iterate and Login ---
        success_count = 0
        fail_count = 0
        for i, cred in enumerate(credentials):
            username = cred['user']
            password = cred['pass']
            self.log_message(f"\n--- Processing Credential {i+1}/{len(credentials)}: {username} ---")

            # 1) Check Driver Validity & Re-initialize if needed
            try:
                _ = self.driver.title # Simple check to see if session is alive
                logging.debug("Driver session appears valid.")
            except WebDriverException as wde:
                self.log_message(f"Warning: Driver session seems invalid ({wde}). Re-initializing...")
                self.close_driver() # Close broken driver
                self.init_driver(headless=False) # Re-init
                if not self.driver:
                    self.log_message("FATAL: Failed to re-initialize driver. Stopping login process.")
                    fail_count = len(credentials) - i # Mark remaining as failed
                    break # Exit the loop

            # 2) Logout first (essential for multi-account login in same browser instance)
            self.log_message("Logging out previous session (if any)...")
            self.logout() # Clears cookies, navigates away

            # 3) Attempt Login
            if self.login_account(username, password):
                success_count += 1
                # Optional: Keep browser open after last successful login? Or close?
                # For now, it stays open until user closes app or starts new process.
            else:
                fail_count += 1
                self.log_message(f"Login failed for {username}. See logs above.")
                # Optional: Pause here? Or continue? Continue is default.
                # input("Press Enter to continue to next account...")

        # --- Cleanup and Summary ---
        self.log_message("\n--- Browser Login Process Finished ---")
        self.log_message(f"Summary: {success_count} successful logins, {fail_count} failed logins.")
        if os.path.exists(local_temp_file):
            try:
                os.remove(local_temp_file)
                self.log_message("Removed temporary login file.")
            except Exception as e_del:
                self.log_message(f"Warning: Could not remove temporary login file {local_temp_file}: {e_del}")

        QMessageBox.information(
            self,
            "Login Process Complete",
            f"Finished processing logins from login.txt for account '{account_name}'.\n\n"
            f"Successful: {success_count}\n"
            f"Failed: {fail_count}\n\n"
            "Check the log messages for details."
        )
        # Decide whether to close the browser window automatically
        # self.close_driver() # Uncomment to close browser after the loop


    # -------------------------
    # Auto Add from JSON Method (REVISED)
    # -------------------------
    def add_account_from_json(self):
        dialog = AddFromJSONDialog(self)
        if dialog.exec_() != QDialog.Accepted: return
        emails_to_find = dialog.get_emails()
        if not emails_to_find: return
        self.log_message(f"--- Starting Auto-Add from Server JSON ({len(emails_to_find)} emails) ---", self.error_text)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        parsed_accounts = {}; failed_parses = []
        for i, email in enumerate(emails_to_find):
            self.log_message(f"Auto-add: Parsing ({i+1}/{len(emails_to_find)}): {email}", self.error_text); QApplication.processEvents()
            local_json_file = None
            try:
                local_json_file = try_load_json_for_account(email)
                with open(local_json_file, 'r') as f: data = json.load(f)
                client_id = data.get('installed', {}).get('client_id')
                client_secret = data.get('installed', {}).get('client_secret')
                if not client_id or not client_secret: raise ValueError("Missing client_id/secret in JSON")
                parsed_accounts[email] = {"client_id": client_id, "client_secret": client_secret}
                self.log_message(f"  Parsed creds for {email} from {local_json_file}", self.error_text)
            except Exception as e_parse:
                self.log_message(f"  FAILED find/parse JSON for {email}: {e_parse}", self.error_text); logging.warning(f"Auto-add parse error for {email}: {e_parse}"); failed_parses.append(email)
            finally:
                if local_json_file and os.path.exists(local_json_file):
                    try: os.remove(local_json_file)
                    except OSError as e_del: logging.warning(f"Could not delete temp JSON {local_json_file}: {e_del}")
        QApplication.restoreOverrideCursor()
        if not parsed_accounts: QMessageBox.information(self, "Auto-Add", "No valid account JSONs found/parsed."); self.log_message("Auto-add: No accounts parsed.", self.error_text); return
        self._handle_account_modification(modification_type="auto_add", parsed_accounts_for_auto_add=parsed_accounts)



    # -------------------------
    # Manual Add Account Dialog Method (REVISED)
    # -------------------------
    def add_account_dialog(self):
        dialog = AddAccountDialog(self)
        if dialog.exec_() != QDialog.Accepted: return
        account_name, client_id, client_secret = dialog.get_account_details()
        if not account_name or '@' not in account_name: QMessageBox.critical(self, "Input Error", "Invalid account name."); return
        if not client_id: QMessageBox.critical(self, "Input Error", "Client ID empty."); return
        if not client_secret: QMessageBox.critical(self, "Input Error", "Client Secret empty."); return
        new_creds = {"client_id": client_id, "client_secret": client_secret}
        self._handle_account_modification(modification_type="add_manual", account_name=account_name, new_creds=new_creds)



    # -------------------------
    # Authentication Methods (Unchanged - rely on global ACCOUNTS)
    # -------------------------
    def authenticate_dropdown(self):
        account_name = self.account_dropdown.currentText()
        if not account_name: QMessageBox.warning(self, "No Account Selected", "Please select an account."); return
        if account_name not in ACCOUNTS: # Use global ACCOUNTS
             QMessageBox.critical(self, "Error", f"Account '{account_name}' not found in loaded configurations. Try refreshing the list.")
             return
        client_id = ACCOUNTS[account_name].get("client_id")
        client_secret = ACCOUNTS[account_name].get("client_secret")
        if not client_id or not client_secret: QMessageBox.critical(self, "Credentials Missing", f"Client ID or Secret missing for '{account_name}'."); return

        self.log_message(f"Attempting authentication via dropdown for: {account_name}", self.error_text)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        if self.google_api.authenticate(account_name, client_id, client_secret):
            QApplication.restoreOverrideCursor()
            self.log_message(f"Authentication successful for {account_name}.", self.error_text)
            QMessageBox.information(self, "Authentication Success", f"Successfully authenticated as:\n{account_name}")
            self.setWindowTitle(f"Google Workspace Manager - {account_name}")
        else:
            QApplication.restoreOverrideCursor()
            self.log_message(f"Authentication failed for {account_name}.", self.error_text)
            self.setWindowTitle("Google Workspace Manager - Not Authenticated")

    def authenticate_listbox(self):
        selected_item = self.accounts_listbox.currentItem()
        if not selected_item: QMessageBox.warning(self, "No Account Selected", "Please select an account from the list."); return
        account_name = selected_item.text()
        if account_name not in ACCOUNTS: # Use global ACCOUNTS
             QMessageBox.critical(self, "Error", f"Account '{account_name}' not found in loaded configurations. Try refreshing the list.")
             return
        client_id = ACCOUNTS[account_name].get("client_id")
        client_secret = ACCOUNTS[account_name].get("client_secret")
        if not client_id or not client_secret: QMessageBox.critical(self, "Credentials Missing", f"Client ID or Secret missing for '{account_name}'."); return

        self.log_message(f"Attempting authentication via listbox for: {account_name}", self.error_text)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        if self.google_api.authenticate(account_name, client_id, client_secret):
            QApplication.restoreOverrideCursor()
            self.log_message(f"Authentication successful for {account_name}.", self.error_text)
            QMessageBox.information(self, "Authentication Success", f"Successfully authenticated as:\n{account_name}")
            index = self.account_dropdown.findText(account_name)
            if index != -1: self.account_dropdown.setCurrentIndex(index)
            self.setWindowTitle(f"Google Workspace Manager - {account_name}")
        else:
            QApplication.restoreOverrideCursor()
            self.log_message(f"Authentication failed for {account_name}.", self.error_text)
            self.setWindowTitle("Google Workspace Manager - Not Authenticated")

    def search_accounts_in_listbox(self, text):
        self.accounts_listbox.clear()
        search_term = text.lower()
        for account in sorted(ACCOUNTS.keys()): # Use global ACCOUNTS
            if search_term in account.lower():
                self.accounts_listbox.addItem(account)


    def confirm_delete_account(self):
        selected_item = self.accounts_listbox.currentItem()
        if not selected_item: QMessageBox.warning(self, "No Account Selected", "Select account to delete."); return
        account_to_delete = selected_item.text()
        reply = QMessageBox.question(self, 'Confirm Deletion', f"Delete config for '{account_to_delete}'?\n(NOT the Google account itself)", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.delete_account_config(account_to_delete)

    def delete_account_config(self, account_name): # Renamed
        op_successful = self._handle_account_modification(modification_type="delete", account_name=account_name)
        if op_successful: # If account config was successfully removed or confirmed not to exist
            logging.info(f"Attempting token removal for deleted account: {account_name}")
            try:
                current_tokens, _ = load_tokens_with_mtime()
                if account_name in current_tokens:
                    del current_tokens[account_name]
                    self.google_api.save_tokens(current_tokens)
                    self.log_message(f"Token for '{account_name}' removed from tokens.json.", self.error_text)
                else: self.log_message(f"Token for '{account_name}' not in tokens.json.", self.error_text)
            except ConnectionError as e_sftp_token:
                 msg = f"SFTP error removing token for '{account_name}': {e_sftp_token}. Config deleted, token might remain."
                 self.log_message(f"WARNING: {msg}", self.error_text); QMessageBox.warning(self, "Token Removal Issue", msg)
            except Exception as e_token:
                 msg = f"Unexpected error removing token for '{account_name}': {e_token}. Config deleted, token might remain."
                 self.log_message(f"ERROR: {msg}", self.error_text); logging.error(msg, exc_info=True); QMessageBox.warning(self, "Token Removal Error", msg)

    def delete_account(self, account_name):
        """Deletes the specified account using optimistic locking."""
        global ACCOUNTS, _last_loaded_mtime # Access globals
        self.log_message(f"Attempting to delete account configuration: {account_name}")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        account_existed = False
        token_existed = False

        try:
            # --- Update ACCOUNTS data with optimistic lock ---
            # 1. Load current state AND mtime from server
            current_server_accounts, last_known_mtime = load_accounts_from_server_with_mtime()
            if last_known_mtime is None and current_server_accounts:
                logging.warning("Cannot perform safe delete as server file mtime is unknown or file missing.")
                QMessageBox.warning(self, "Operation Skipped", "Could not get server file status. Delete skipped. Please Refresh.")
                raise ConnectionError("Server mtime check failed for safe delete.")

            # 2. Perform deletion in memory
            accounts_to_write = current_server_accounts.copy()
            if account_name in accounts_to_write:
                del accounts_to_write[account_name]
                account_existed = True
                self.log_message(f"Account '{account_name}' marked for deletion.")
            else:
                self.log_message(f"Account '{account_name}' not found in current server data. No change needed.")

            # 3. Proceed only if account actually existed in the loaded data
            if account_existed:
                # 4. Check mtime AGAIN before writing
                target_write_path = _last_loaded_accounts_path or REMOTE_ACCOUNTS_PATH_PRIMARY
                current_mtime = check_server_mtime(target_write_path)

                if current_mtime is None:
                     self.log_message("ERROR: Could not verify server file status before saving deleted account.")
                     QMessageBox.critical(self, "Save Error", "Failed to check server file status before saving. Save aborted.")
                elif current_mtime != last_known_mtime:
                    # CONFLICT DETECTED!
                    self.log_message(f"CONFLICT: Server file changed (mtime {current_mtime} != {last_known_mtime}). Delete aborted.")
                    QMessageBox.warning(self, "Conflict Detected", "Account configuration modified by another instance.\nPlease Refresh the list and try deleting again.")
                    self.refresh_accounts() # Force refresh
                else:
                    # 5. Safe to Write
                    self.log_message(f"No conflict detected (mtime: {current_mtime}). Saving deleted account list...")
                    backup_local_file(LOCAL_ACCOUNTS_FILE)
                    with open(LOCAL_ACCOUNTS_FILE, 'w') as f_local_w:
                        json.dump(accounts_to_write, f_local_w, indent=4)

                    save_to_server(LOCAL_ACCOUNTS_FILE, target_write_path)

                    # Update globals *after* successful save
                    ACCOUNTS = accounts_to_write
                    _last_loaded_mtime = check_server_mtime(target_write_path)
                    self.log_message(f"Successfully removed '{account_name}' from accounts.json locally and on server.")
            else:
                 # If account didn't exist in loaded data, update globals anyway to match loaded state
                 ACCOUNTS = current_server_accounts
                 _last_loaded_mtime = last_known_mtime


            # --- Update TOKENS data (local and server) ---
            # This doesn't strictly need the optimistic lock on accounts.json,
            # but should happen after the account deletion is confirmed (or found not to exist).
            if account_name in self.google_api.tokens:
                del self.google_api.tokens[account_name]
                token_existed = True
                self.google_api.save_tokens() # Handles local/server save
                self.log_message(f"Removed token for '{account_name}'.")
            else:
                self.log_message(f"Token for '{account_name}' not found in cache.")

            # Refresh UI from the final global ACCOUNTS state
            self.load_accounts_to_ui()

            if account_existed or token_existed:
                 QMessageBox.information(self, "Deletion Complete", f"Configuration for '{account_name}' removed.")
            else:
                 QMessageBox.warning(self, "Not Found", f"Configuration for '{account_name}' was not found in server data.")

        except ConnectionError as e_conn:
             error_msg = f"Failed to delete account {account_name} due to SFTP error: {e_conn}"
             logging.error(error_msg, exc_info=False)
             self.log_message(f"ERROR: {error_msg}")
             QMessageBox.critical(self, "SFTP Error", error_msg)
             # Refresh UI to show potentially stale data
             self.load_accounts_to_ui()
        except Exception as e:
            error_msg = f"Unexpected error deleting account {account_name}: {e}"
            logging.error(error_msg, exc_info=True)
            self.log_message(f"ERROR: {error_msg}")
            QMessageBox.critical(self, "Deletion Error", error_msg)
            # Refresh UI
            self.load_accounts_to_ui()
        finally:
            QApplication.restoreOverrideCursor()


    def backup_files(self):
        # ... (implementation unchanged) ...
        self.log_message("Starting backup process...")
        ensure_backup_dir() # Make sure backup dir exists
        files_to_backup = [LOCAL_ACCOUNTS_FILE, LOCAL_TOKEN_FILE]
        success_count = 0
        fail_count = 0

        for file_path in files_to_backup:
            if os.path.exists(file_path):
                 try:
                     backup_local_file(file_path) # Function now includes timestamp
                     self.log_message(f"Successfully backed up: {os.path.basename(file_path)}")
                     success_count += 1
                 except Exception as e:
                      error_msg = f"Failed to back up {os.path.basename(file_path)}: {e}"
                      self.log_message(f"ERROR: {error_msg}")
                      logging.error(error_msg)
                      fail_count += 1
            else:
                 self.log_message(f"Skipping backup: {os.path.basename(file_path)} does not exist locally.")

        result_message = f"Backup process completed.\n\nSuccessful backups: {success_count}\nFailed backups: {fail_count}"
        if fail_count > 0:
             QMessageBox.warning(self, "Backup Partially Failed", result_message + "\nCheck logs for details.")
        elif success_count > 0:
             QMessageBox.information(self, "Backup Complete", result_message)
        else:
            QMessageBox.information(self, "Backup Skipped", "No local files found to back up.")



    # -------------------------
    # User Listing & Basic Actions Methods (Tab 1)
    # -------------------------
    def retrieve_active_users(self):
        # Log to self.error_text (SMTP log on Tab 2)
        if not self.google_api.service: QMessageBox.warning(self, "Not Authenticated", "Please authenticate first."); return
        self.log_message("Retrieving all users for listing...", self.error_text)
        self.user_list_text.clear(); self.user_count_label.setText("Total Users: Fetching...")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            all_users, page_token, total_fetched = [], None, 0
            while True:
                results = self.google_api.service.users().list(customer='my_customer', orderBy='email', maxResults=500, projection='full', fields='nextPageToken,users(primaryEmail,name/givenName,name/familyName,suspended,isAdmin)', pageToken=page_token).execute()
                users_in_page = results.get('users', [])
                all_users.extend(users_in_page); total_fetched += len(users_in_page)
                self.user_count_label.setText(f"Total Users: Fetching... ({total_fetched})"); QApplication.processEvents()
                page_token = results.get('nextPageToken')
                if not page_token: break
            self.log_message(f"Finished fetching {len(all_users)} users.", self.error_text)
            admin_color, suspended_color = "orange", "red"; active_color = "#4CAF50" if self.dark_theme_enabled else "green"
            admin_count, suspended_count, active_count = 0, 0, 0; html_lines = []
            for user in all_users:
                email, is_admin, is_suspended = user.get('primaryEmail', 'N/A'), user.get('isAdmin', False), user.get('suspended', False)
                text_color = admin_color if is_admin else (suspended_color if is_suspended else active_color)
                if is_admin: admin_count +=1
                elif is_suspended: suspended_count +=1
                else: active_count +=1
                html_lines.append(f"<span style='color:{text_color}'>{html.escape(email)}</span>")
            self.user_list_text.setHtml("<br>".join(html_lines))
            count_summary = (f"Total: {len(all_users)} | <font color='{active_color}'>Active: {active_count}</font> | <font color='{suspended_color}'>Suspended: {suspended_count}</font> | <font color='{admin_color}'>Admin: {admin_count}</font>")
            self.user_count_label.setText(count_summary)
        except HttpError as err: self.log_message(f"ERROR: API Error users: {err}", self.error_text); QMessageBox.critical(self, "API Error", str(err)); self.user_count_label.setText("Total Users: Error")
        except Exception as e: logging.error(f"Retrieve users error: {e}", exc_info=True); self.log_message(f"ERROR: Retrieve users: {e}", self.error_text); QMessageBox.critical(self, "Error", str(e)); self.user_count_label.setText("Total Users: Error")
        finally: QApplication.restoreOverrideCursor()

    def clear_user_list(self):
        self.user_list_text.clear(); self.user_count_label.setText("Total Users: 0")
        self.log_message("User list cleared.", self.error_text) # Log to self.error_text

    def select_all_copy(self):
        if self.user_list_text.toPlainText(): self.user_list_text.selectAll(); self.user_list_text.copy(); self.log_message("All users copied.", self.error_text)
        else: self.log_message("User list empty, nothing to copy.", self.error_text) # Log to self.error_text

    def update_password_for_listed_users(self):
        # Log to self.error_text
        if not self.google_api.service: QMessageBox.warning(self, "Not Authenticated", "Authenticate first."); return
        new_pass = self.password_entry.text()
        if not new_pass: QMessageBox.warning(self, "Input Needed", "Enter new password."); return
        if len(new_pass) < 8: QMessageBox.warning(self, "Weak Password", "Password >= 8 chars."); return
        emails = [line.strip() for line in self.user_list_text.toPlainText().splitlines() if '@' in line.strip()]
        if not emails: QMessageBox.warning(self, "No Emails", "No valid emails in list."); return
        reply = QMessageBox.question(self, 'Confirm Update', f"Update pass to '{new_pass}' for {len(emails)} users?", QMessageBox.Yes|QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.No: self.log_message("Password update cancelled.", self.error_text); return
        self.log_message(f"--- Starting Pass Update for {len(emails)} Users ---", self.error_text); QApplication.setOverrideCursor(Qt.WaitCursor)
        succ, fail, proc = 0,0,0
        for email in emails:
            proc+=1; self.log_message(f"Updating ({proc}/{len(emails)}): {email}", self.error_text); QApplication.processEvents()
            if self.google_api.update_user(email, {'password': new_pass, 'changePasswordAtNextLogin': False}): succ+=1
            else: fail+=1
        QApplication.restoreOverrideCursor(); self.log_message("--- Pass Update Finished ---", self.error_text)
        QMessageBox.information(self, "Update Results", f"Attempts: {len(emails)}, OK: {succ}, Fail: {fail}"); self.password_entry.clear()

    def retrieve_subdomains(self):
        if not self.google_api.service:
            QMessageBox.warning(self, "Not Authenticated", "Authenticate first.")
            return

        self.log_message("Retrieving grouped domain information (order based on API response sequence)...", self.error_text)
        self.subdomain_display.clear()
        QApplication.setOverrideCursor(Qt.WaitCursor)

        try:
            # grouped_domains_list is: List[Tuple[parent_info_dict, List[sub_info_dict]]]
            grouped_domains_list = self.google_api.get_subdomains()

            if not grouped_domains_list:
                self.log_message("No verified domains (or no parent groups) found for this account.", self.error_text)
                self.subdomain_display.setPlainText("No verified domains found.")
                QMessageBox.information(self, "No Domains", "No verified domains are associated with this account.")
                return

            self.log_message(f"Found {len(grouped_domains_list)} parent domain group(s). Displaying with usage status...", self.error_text)

            html_lines = []

            if self.dark_theme_enabled:
                red_hex = "#F48FB1"    # Used domain name
                green_hex = "#A5D6A7"  # Unused domain name
                desc_text_hex = "#E0E0E0" # Description text
                parent_prefix_color = "#BBDEFB" # Light blue for parent prefix
            else:
                red_hex = "#D32F2F"
                green_hex = "#388E3C"
                desc_text_hex = "#212121"
                parent_prefix_color = "#0D47A1" # Dark blue for parent prefix

            def format_domain_line(info_dict, is_subdomain=False):
                d_name = info_dict['domain_name']
                d_is_used = info_dict['used_active']
                d_active_count = info_dict['count_active']
                d_total_count = info_dict['count_total']

                name_color = red_hex if d_is_used else green_hex
                status_str = "Active Users Present" if d_is_used else "No Active Users"
                count_str = f"(Active: {d_active_count}, Total: {d_total_count})"
                
                indent = "    " if is_subdomain else ""
                
                # Domain Name: Colored Red/Green, Bold
                # Description: Fixed color
                line = (
                    f'{indent}<span style="color:{name_color}; font-weight:bold;">{html.escape(d_name)}</span>'
                    f' <span style="color:{desc_text_hex};"> - {status_str} {count_str}</span>'
                )
                return line

            for parent_info, subdomains_list in grouped_domains_list:
                # Display parent domain
                html_lines.append(format_domain_line(parent_info, is_subdomain=False))
                
                # Display its subdomains
                for sub_info in subdomains_list:
                    html_lines.append(format_domain_line(sub_info, is_subdomain=True))
                
                if subdomains_list: # Add a small visual break if there were subdomains
                    html_lines.append("<br>") # Or just let the next parent start

            # Remove last <br> if it exists to prevent extra space at the end
            if html_lines and html_lines[-1] == "<br>":
                html_lines.pop()

            self.subdomain_display.setHtml("<br>".join(html_lines))

        except Exception as e:
            logging.error(f"Domain display error: {e}", exc_info=True)
            self.log_message(f"ERROR: Domain display: {e}", self.error_text)
            self.subdomain_display.setPlainText("Error retrieving domain information. Please check logs.")
        finally:
            QApplication.restoreOverrideCursor()
            
    def clear_subdomain_display_ui(self): # Renamed from clear_subdomain_display
        self.subdomain_display.clear()
        self.log_message("Subdomain display cleared.", self.error_text) # Log to self.error_text

    def load_suspended_users(self):
        # Log to self.error_text
        if not self.google_api.service: QMessageBox.warning(self, "Not Authenticated", "Authenticate first."); return
        self.log_message("Loading suspended users...", self.error_text); self.suspended_users_list.clear(); QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            suspended = self.google_api.list_suspended_users()
            if suspended:
                emails = sorted([user['primaryEmail'] for user in suspended if 'primaryEmail' in user])
                self.suspended_users_list.addItems(emails); self.log_message(f"Loaded {len(emails)} suspended users.", self.error_text); QMessageBox.information(self, "Loaded", f"Found {len(emails)} suspended users.")
            else: self.log_message("No suspended users found.", self.error_text); QMessageBox.information(self, "No Users", "No suspended users.")
        except Exception as e: logging.error(f"Load suspended error: {e}", exc_info=True); self.log_message(f"ERROR: Load suspended: {e}", self.error_text)
        finally: QApplication.restoreOverrideCursor()

    def unsuspend_selected_users(self):
        # Log to self.error_text
        if not self.google_api.service: QMessageBox.warning(self, "Not Authenticated", "Authenticate first."); return
        selected = self.suspended_users_list.selectedItems()
        if not selected: QMessageBox.warning(self, "No Selection", "Select users to unsuspend."); return
        emails = [item.text() for item in selected]; preview = "\\n".join(emails[:10]) + ("\\n..." if len(emails) > 10 else "")
        reply = QMessageBox.question(self, 'Confirm Unsuspend', f"Unsuspend {len(emails)} user(s)?\\n\\n{preview}", QMessageBox.Yes|QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.No: self.log_message("Unsuspend cancelled.", self.error_text); return
        self.log_message(f"--- Starting Unsuspend for {len(emails)} Users ---", self.error_text); QApplication.setOverrideCursor(Qt.WaitCursor)
        succ, fail = 0,0
        for email in emails:
            self.log_message(f"Unsuspending: {email}", self.error_text); QApplication.processEvents()
            if self.google_api.unsuspend_user(email):
                succ+=1; items = self.suspended_users_list.findItems(email, Qt.MatchExactly)
                if items: self.suspended_users_list.takeItem(self.suspended_users_list.row(items[0]))
            else: fail+=1
        QApplication.restoreOverrideCursor(); self.log_message("--- Unsuspend Finished ---", self.error_text)
        summary = f"Attempts: {len(emails)}, OK: {succ}, Fail: {fail}" + ("\\n\\nNote: Abuse suspensions require Admin Console." if fail > 0 else "")
        QMessageBox.information(self, "Unsuspend Results", summary)

    def browse_csv_for_creation(self):
        # Log to self.error_text (SMTP log on Tab 2)
        file_path, _ = QFileDialog.getOpenFileName(self, "Select CSV for User Creation", "", "CSV files (*.csv)")
        if file_path: self.create_csv_file_entry.setText(file_path); self.log_message(f"Selected CSV for creation: {file_path}", self.error_text)

    def bulk_create_users_from_csv(self):
        # Log to self.error_text
        if not self.google_api.service: QMessageBox.warning(self, "Not Authenticated", "Authenticate first."); return
        file_path = self.create_csv_file_entry.text()
        if not file_path or not os.path.exists(file_path): QMessageBox.critical(self, "File Error", "Select valid CSV."); return
        self.log_message(f"--- Starting Bulk User Creation from CSV: {file_path} ---", self.error_text); QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            users_df = pd.read_csv(file_path, dtype=str).fillna(''); self.log_message(f"Read {len(users_df)} rows.", self.error_text)
            column_map, possible_mappings = {}, {'primaryEmail': ['email address', 'email', 'primary email', 'user email'],'givenName': ['first name', 'firstname', 'given name', 'givenname'],'familyName': ['last name', 'lastname', 'family name', 'familyname', 'surname'],'password': ['password', 'initial password'],'orgUnitPath': ['org unit path', 'org unit', 'orgunitpath', 'ou'],'changePasswordAtNextLogin': ['change password at next sign-in', 'force password change', 'changepassword']}
            actual_cols_lower = {col.lower().strip(): col for col in users_df.columns}
            for field, alts in possible_mappings.items():
                found_orig_col = None
                for alt in alts:
                    if alt in actual_cols_lower: found_orig_col = actual_cols_lower[alt]; column_map[field] = found_orig_col; logging.info(f"Mapped '{field}' to '{found_orig_col}'"); break
                if field in ['primaryEmail', 'givenName', 'familyName', 'password'] and not found_orig_col: raise ValueError(f"Required column for '{field}' not found. Expected: {', '.join(alts)}")
            succ, fail, total_rows = 0,0,len(users_df)
            for index, row in users_df.iterrows():
                self.log_message(f"Processing CSV row {index+2}/{total_rows+1}...", self.error_text); QApplication.processEvents()
                email, first, last, pword = str(row[column_map['primaryEmail']]).strip(), str(row[column_map['givenName']]).strip(), str(row[column_map['familyName']]).strip(), str(row[column_map['password']]).strip()
                if not email or '@' not in email or not first or not last or not pword: self.log_message(f"  Skipping row {index+2}: Missing required.", self.error_text); fail +=1; continue
                user_info = {"primaryEmail": email, "name": {"givenName": first, "familyName": last}, "password": pword, "changePasswordAtNextLogin": False, "orgUnitPath": "/"}
                if 'orgUnitPath' in column_map and row[column_map['orgUnitPath']]:
                    org_path = str(row[column_map['orgUnitPath']]).strip()
                    if not org_path.startswith('/'): self.log_message(f"  Warn row {index+2}: Invalid OU '{org_path}'. Using '/'.", self.error_text)
                    else: user_info["orgUnitPath"] = org_path
                if 'changePasswordAtNextLogin' in column_map and str(row[column_map['changePasswordAtNextLogin']]).strip().lower() in ['true','yes','1']: user_info['changePasswordAtNextLogin'] = True
                self.log_message(f"  Attempting create: {email}", self.error_text)
                created_email = self.google_api.create_user(user_info)
                if created_email: self.log_message(f"  SUCCESS: '{created_email}' created/unsuspended.", self.error_text); succ +=1
                else: self.log_message(f"  FAILED: Creation for '{email}'. See logs.", self.error_text); fail +=1
            summary = f"Bulk Create Finished.\nTotal: {total_rows}\nSucceeded: {succ}\nFailed/Skipped: {fail}"
            self.log_message(summary, self.error_text); QMessageBox.information(self, "Creation Complete", summary)
        except ValueError as ve: self.log_message(f"ERROR: {ve}", self.error_text); QMessageBox.critical(self, "CSV Error", str(ve))
        except pd.errors.EmptyDataError: self.log_message("ERROR: CSV empty.", self.error_text); QMessageBox.critical(self, "CSV Error", "CSV empty.")
        except FileNotFoundError: self.log_message(f"ERROR: File not found: {file_path}", self.error_text); QMessageBox.critical(self, "File Error", f"File not found: {file_path}")
        except Exception as e: logging.error(f"CSV Create Error: {e}", exc_info=True); self.log_message(f"FATAL: {e}", self.error_text); QMessageBox.critical(self, "Processing Error", str(e))
        finally: QApplication.restoreOverrideCursor()

    # In MainWindow class
    def create_random_users(self):
            # Log to self.error_text
            if not self.google_api.service: QMessageBox.warning(self, "Not Authenticated", "Authenticate first."); return
            num_str, domain_str = self.random_user_count_entry.text().strip(), self.random_user_domain_entry.text().strip()
            
            # Input validation for num_str
            num = 0 # Initialize num
            try:
                num = int(num_str)
                if num <= 0:
                    QMessageBox.critical(self, "Input Error", "Please enter a valid positive number of users.")
                    return
            except ValueError:
                QMessageBox.critical(self, "Input Error", "Please enter a valid positive number of users.")
                return
    
            if not domain_str or '@' in domain_str or '.' not in domain_str:
                QMessageBox.critical(self, "Input Error", "Please enter a valid domain (e.g., domain.com).")
                return
            
            pword = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            self.log_message(f"Generated password for random users: {pword}", self.error_text)
            self.log_message(f"--- Starting Random Create ({num} in '{domain_str}') ---", self.error_text)
            QApplication.setOverrideCursor(Qt.WaitCursor)
            succ, fail, created_emails = 0, 0, []
            
            for i in range(num):
                self.log_message(f"Creating user {i+1}/{num}...", self.error_text)
                QApplication.processEvents()
                first, last = self.generate_random_name()
                attempts = 0
                email = "" # Initialize email variable before the loop
    
                # Corrected while loop structure
                while attempts < 5:
                    alias = self.generate_random_alias(first, last)
                    email = f"{alias}@{domain_str}"
                    if email not in created_emails:
                        break  # Found a unique email
                    attempts += 1
                else: # This else belongs to the while loop (executes if loop finished without break)
                    self.log_message(f"  Skipping user {i+1}: Could not generate unique alias for {first} {last} after {attempts} attempts.", self.error_text)
                    fail += 1
                    continue # Continue to the next user in the for loop
                
                user_info = {"primaryEmail": email, "name": {"givenName": first, "familyName": last}, "password": pword, "changePasswordAtNextLogin": False, "orgUnitPath": "/"}
                self.log_message(f"  Attempting create: {email} ({first} {last})", self.error_text)
                created_api = self.google_api.create_user(user_info)
                
                if created_api:
                    self.log_message(f"  SUCCESS: '{created_api}' created.", self.error_text)
                    created_emails.append(created_api) # Add successfully created email to the list
                    succ += 1
                else:
                    self.log_message(f"  FAILED: Creation for '{email}'. See logs.", self.error_text)
                    fail += 1
                    
            QApplication.restoreOverrideCursor()
            self.log_message("--- Random Create Finished ---", self.error_text)
            QMessageBox.information(self, "Creation Complete", f"Random Create Done.\nAttempts: {num}\nOK: {succ}\nFail: {fail}\nPass: {pword}")
    


    def generate_random_name(self):
        """Generates a random first and last name."""
        # Could add more diverse name generation later if needed
        fake = Faker()
        return fake.first_name(), fake.last_name()

    def generate_random_alias(self, first_name, last_name):
        """Generates a somewhat unique alias."""
        # Simple format, might need adjustment for very large domains to avoid collisions
        fn_clean = re.sub(r'\W+', '', first_name.lower())
        ln_clean = re.sub(r'\W+', '', last_name.lower())
        num = random.randint(1, 999) # Increase range slightly
        return f"{fn_clean}.{ln_clean}{num}"



    def change_domain_specified_users(self):
        # Log to self.error_text
        if not self.google_api.service: QMessageBox.warning(self, "Not Authenticated", "Authenticate first."); return
        curr_dom, new_dom, emails_raw = self.specific_current_domain_entry.text().strip(), self.specific_new_domain_entry.text().strip(), self.specified_users_text.toPlainText().strip()
        if not curr_dom or '.' not in curr_dom: QMessageBox.warning(self, "Input Error", "Invalid 'Current Domain Suffix'."); return
        if not new_dom or '.' not in new_dom: QMessageBox.warning(self, "Input Error", "Invalid 'New Domain Suffix'."); return
        if curr_dom.lower() == new_dom.lower(): QMessageBox.warning(self, "Input Error", "Domains same."); return
        if not emails_raw: QMessageBox.warning(self, "Input Error", "Enter emails."); return
        emails = [e.strip() for e in emails_raw.splitlines() if e.strip() and '@' in e.strip()]
        if not emails: QMessageBox.warning(self, "Input Error", "No valid emails."); return
        reply = QMessageBox.question(self, 'Confirm Change', f"Change domain from '{curr_dom}' to '{new_dom}' for {len(emails)} users?", QMessageBox.Yes|QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.No: self.log_message("Specific domain change cancelled.", self.error_text); return
        self.log_message(f"--- Starting Specific Domain Change ({len(emails)}) ---", self.error_text); self.log_message(f"Changing: '@{curr_dom}' -> '@{new_dom}'", self.error_text); QApplication.setOverrideCursor(Qt.WaitCursor)
        succ, fail, skip = 0,0,0
        for i, current_email in enumerate(emails):
            self.log_message(f"Processing ({i+1}/{len(emails)}): {current_email}", self.error_text); QApplication.processEvents()
            expected_suffix = f"@{curr_dom}"
            if not current_email.lower().endswith(expected_suffix.lower()): self.log_message(f"  Skipping: '{current_email}' no match '{expected_suffix}'.", self.error_text); skip+=1; continue
            alias = current_email[:-len(expected_suffix)]; new_email_val = f"{alias}@{new_dom}"
            self.log_message(f"  Attempting update: {current_email} -> {new_email_val}", self.error_text)
            if self.google_api.update_user(current_email, {'primaryEmail': new_email_val}): self.log_message(f"  SUCCESS: {current_email} -> {new_email_val}", self.error_text); succ+=1
            else: self.log_message(f"  FAILED: Update for {current_email}. See logs.", self.error_text); fail+=1
        QApplication.restoreOverrideCursor(); self.log_message("--- Specific Domain Change Finished ---", self.error_text)
        QMessageBox.information(self, "Change Results", f"Specific Domain Change Done.\nTotal: {len(emails)}\nOK: {succ}\nFail: {fail}\nSkipped: {skip}")

    def delete_specified_users(self):
        # Log to self.error_text
        if not self.google_api.service: QMessageBox.warning(self, "Not Authenticated", "Authenticate first."); return
        emails_raw = self.delete_users_text.toPlainText().strip()
        if not emails_raw: QMessageBox.warning(self, "Input Error", "Enter emails to delete."); return
        emails = [e.strip() for e in emails_raw.splitlines() if e.strip() and '@' in e.strip()]
        if not emails: QMessageBox.warning(self, "Input Error", "No valid emails."); return
        preview = "\\n".join(emails[:10]) + ("\\n..." if len(emails) > 10 else "")
        reply = QMessageBox.question(self, 'Confirm Deletion', f"!! WARNING !!\\nPermanently delete {len(emails)} user(s)?\\n\\n{preview}\\n\\nThis is IRREVERSIBLE.", QMessageBox.Yes|QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.No: self.log_message("Specific user deletion cancelled.", self.error_text); return
        self.log_message(f"--- Starting Specific Deletion ({len(emails)}) ---", self.error_text); QApplication.setOverrideCursor(Qt.WaitCursor)
        succ, fail = 0,0
        for i, email in enumerate(emails):
            self.log_message(f"Processing ({i+1}/{len(emails)}): Deleting {email}", self.error_text); QApplication.processEvents()
            if self.google_api.delete_user(email): succ+=1
            else: fail+=1; time.sleep(0.1)
        QApplication.restoreOverrideCursor(); self.log_message("--- Specific Deletion Finished ---", self.error_text)
        QMessageBox.information(self, "Deletion Results", f"Specific Deletion Done.\nTotal: {len(emails)}\nDeleted/Gone: {succ}\nFailed: {fail}")


    # ----------------------------------
    # SMTP & CSV Generation Methods (Tab 2)
    # ----------------------------------

    def generate_csv(self):
        # Log to self.error_text (SMTP log on Tab 2)
        num_str, domain_str, pword = self.csv_num_users_entry.text().strip(), self.csv_domain_entry.text().strip(), self.csv_password_entry.text().strip()
        if not num_str.isdigit() or int(num_str) <= 0: QMessageBox.critical(self, "Input Error", "Valid positive num users for CSV."); return; num = int(num_str)
        if not domain_str or '@' in domain_str or '.' not in domain_str: QMessageBox.critical(self, "Input Error", "Valid domain (e.g., domain.com)."); return
        if not pword: QMessageBox.critical(self, "Input Error", "Enter default pass for CSV."); return
        if len(pword) < 8: QMessageBox.warning(self, "Weak Password", "Pass < 8 chars. Consider stronger.")
        self.log_message(f"Generating CSV for {num} users in '{domain_str}'...", self.error_text); QApplication.setOverrideCursor(Qt.WaitCursor)
        users_data = []
        for i in range(num):
            first, last = self.generate_random_name(); alias = self.generate_random_alias(first, last); email = f"{alias}@{domain_str}"; tries = 0
            while any(u['Email Address [Required]'] == email for u in users_data) and tries < 10: alias = self.generate_random_alias(first, last); email = f"{alias}@{domain_str}"; tries+=1
            if tries == 10: logging.warning(f"Could not gen unique alias for CSV row {i+1}.")
            user_info = {"First Name [Required]": first, "Last Name [Required]": last, "Email Address [Required]": email, "Password [Required]": pword, "Password Hash Function [UPLOAD ONLY]": "", "Org Unit Path [Required]": "/", "New Primary Email [UPLOAD ONLY]": "", "Recovery Email": "", "Home Secondary Email": "", "Work Secondary Email": "", "Recovery Phone [MUST BE IN THE E.164 FORMAT]": "", "Work Phone": "", "Home Phone": "", "Mobile Phone": "", "Work Address": "", "Home Address": "", "Employee ID": "", "Employee Type": "", "Employee Title": "", "Manager Email": "", "Department": "", "Cost Center": "", "Building ID": "", "Floor Name": "", "Floor Section": "", "Change Password at Next Sign-In": "False", "New Status [UPLOAD ONLY]": "", "Advanced Protection Program enrollment": "False"}
            users_data.append(user_info)
        df = pd.DataFrame(users_data); csv_gen_dir = os.path.join(BULK_CHANGE_DIR, 'Generated_CSVs'); ensure_dir(csv_gen_dir)
        safe_domain = re.sub(r'[^\w\-.]', '_', domain_str); ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = os.path.join(csv_gen_dir, f"{safe_domain}_Generated_{num}_Users_{ts}.csv")
        try: df.to_csv(save_path, index=False, encoding='utf-8'); self.log_message(f"Generated CSV for {num} users.\nSaved to:\n{save_path}", self.error_text); QMessageBox.information(self, "CSV Gen Complete", f"Generated CSV for {num} users.\nSaved to:\n{save_path}")
        except Exception as e: logging.error(f"Save CSV Error: {e}", exc_info=True); self.log_message(f"ERROR: {e}", self.error_text); QMessageBox.critical(self, "File Save Error", str(e))
        finally: QApplication.restoreOverrideCursor()



    def log_error(self, error_message):
        """Logs SMTP errors to the GUI and dedicated files."""
        # Ensure logging happens on the GUI thread
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_msg = f"[{timestamp}] {error_message}"
        try:
             # Use invokeMethod for thread safety
             # Ensure self.error_text (the SMTP log widget) exists
             if hasattr(self, 'error_text'):
                 QMetaObject.invokeMethod(self.error_text, "appendPlainText", Qt.QueuedConnection, Q_ARG(str, formatted_msg))
             else:
                 print(f"SMTP Log Widget Error: {formatted_msg}") # Console fallback
        except Exception as e:
             print(f"Error logging SMTP error to GUI: {e}. Message: {formatted_msg}") # Fallback

        # Log to file logger as well
        logging.warning(f"SMTP Log: {error_message}")

        # Append to specific error files (Consider moving file writing out of here if performance is critical)
        # Note: Continuous appending might be slow. Batching writes could be better.
        # For simplicity, we keep append here. Ensure file handles are closed properly (use 'with open').
        log_dir = os.path.join(os.getcwd(), "SMTP_Logs") # Put logs in a subfolder
        ensure_dir(log_dir)

        # Determine which file to write to based on the error message content
        if "Status: Good" in error_message:
             filepath = os.path.join(log_dir, 'Good.txt')
        elif "Error: Application-specific password required" in error_message:
             filepath = os.path.join(log_dir, 'App_Password_Required.txt')
        elif "Error: Wrong username or password" in error_message or "Authentication failed" in error_message:
             filepath = os.path.join(log_dir, 'Wrong_Username_Password.txt')
        elif "Error:" in error_message: # Catch other specific errors logged with "Error:" prefix
             filepath = os.path.join(log_dir, 'Bad.txt')
        else: # Fallback for unexpected formats or connection issues before login attempt
             filepath = os.path.join(log_dir, 'Other_Errors.txt')

        try:
            with open(filepath, 'a', encoding='utf-8') as error_file:
                error_file.write(formatted_msg + '\n')
        except Exception as e:
             logging.error(f"Failed to write SMTP log to {filepath}: {e}")


    def send_test_email(self):
        """Initiates the SMTP testing process using threading."""
        smtp_host = self.smtp_server_dropdown.currentText().strip()
        smtp_port_str = self.smtp_port_entry.text().strip()
        recipient_email = self.recipient_email_entry.text().strip()
        smtp_credentials_raw = self.smtp_credentials_text.toPlainText().strip()

        # --- Validation ---
        if not smtp_host:
             QMessageBox.critical(self, "Input Error", "Please enter the SMTP Server address.")
             return
        if not smtp_port_str or not smtp_port_str.isdigit():
            QMessageBox.critical(self, "Input Error", "Please enter a valid SMTP Port number.")
            return
        smtp_port = int(smtp_port_str)
        if not recipient_email or '@' not in recipient_email:
            QMessageBox.critical(self, "Input Error", "Please enter a valid Recipient Email address.")
            return
        if not smtp_credentials_raw:
             QMessageBox.critical(self, "Input Error", "Please enter SMTP credentials (email:password, one per line).")
             return

        # Parse credentials
        account_lines = [line.strip() for line in smtp_credentials_raw.splitlines() if line.strip() and ':' in line.strip()]
        if not account_lines:
             QMessageBox.critical(self, "Input Error", "No valid credential lines (email:password) found.")
             return

        total_accounts = len(account_lines)
        self.log_error(f"--- Starting SMTP Test for {total_accounts} Accounts ---")
        self.log_error(f"Server: {smtp_host}:{smtp_port}, Recipient: {recipient_email}")

        self.stop_sending_emails = False # Reset interruption flag
        self.send_test_email_btn.setEnabled(False) # Disable button during sending
        self.interrupt_send_btn.setEnabled(True) # Enable interrupt button

        # Use a lock for thread-safe logging to GUI/files via log_error
        log_lock = threading.Lock()
        self.active_smtp_threads = [] # Keep track of threads

        # Start a thread for each credential line
        for i, line in enumerate(account_lines):
            if self.stop_sending_emails:
                self.log_error("Email sending interrupted by user.")
                break # Stop creating new threads

            thread = threading.Thread(target=self.send_email_worker, args=(line, recipient_email, smtp_host, smtp_port, log_lock, i+1, total_accounts), daemon=True)
            self.active_smtp_threads.append(thread)
            thread.start()

        # Start a monitoring thread to re-enable the button when all workers are done
        monitor_thread = threading.Thread(target=self.monitor_smtp_threads, daemon=True)
        monitor_thread.start()


    def monitor_smtp_threads(self):
        """Waits for all SMTP worker threads to complete."""
        for thread in self.active_smtp_threads:
            thread.join() # Wait for each thread to finish

        # All threads finished, re-enable button on GUI thread
        QMetaObject.invokeMethod(self.send_test_email_btn, "setEnabled", Qt.QueuedConnection, Q_ARG(bool, True))
        QMetaObject.invokeMethod(self.interrupt_send_btn, "setEnabled", Qt.QueuedConnection, Q_ARG(bool, False))
        self.log_error("--- SMTP Test Finished ---")


    def send_email_worker(self, account_info, recipient_email, smtp_server, smtp_port, lock, count, total):
        """Worker function executed by each SMTP test thread."""
        if self.stop_sending_emails: # Check flag again within the thread
            return

        # Parse email:password
        try:
            email, password = account_info.strip().split(':', 1)
            email = email.strip()
            password = password.strip()
            if not email or not password:
                raise ValueError("Empty email or password")
        except ValueError:
            with lock:
                self.log_error(f"({count}/{total}) Invalid format: {account_info} - Skipping")
            return

        # Construct email message (simple text)
        subject = f"SMTP Test from GBot ({email})"
        body = f"This is an automated test email sent from the GBot application.\nSender: {email}\nRecipient: {recipient_email}\nServer: {smtp_server}:{smtp_port}"
        message = f"Subject: {subject}\nFrom: {email}\nTo: {recipient_email}\n\n{body}"

        log_prefix = f"({count}/{total}) {email}: "

        try:
            # Establish connection (use timeout)
            # Try common scenarios: STARTTLS on 587, SSL/TLS on 465
            smtp_conn = None
            if smtp_port == 465:
                 # Use SMTP_SSL for implicit TLS on port 465
                 smtp_conn = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=20) # Increased timeout
                 log_msg_conn = f"{log_prefix}Connecting via SMTP_SSL..."
            else:
                 # Assume STARTTLS for other ports (like 587)
                 smtp_conn = smtplib.SMTP(smtp_server, smtp_port, timeout=20)
                 log_msg_conn = f"{log_prefix}Connecting via SMTP..."

            with lock: self.log_error(log_msg_conn) # Log connection attempt

            with smtp_conn: # Context manager handles quit()
                 if smtp_port != 465:
                     with lock: self.log_error(f"{log_prefix}Attempting STARTTLS...")
                     smtp_conn.starttls() # Upgrade connection to TLS
                     with lock: self.log_error(f"{log_prefix}STARTTLS successful.")

                 with lock: self.log_error(f"{log_prefix}Attempting login...")
                 smtp_conn.login(email, password)
                 with lock: self.log_error(f"{log_prefix}Login successful.")

                 if self.stop_sending_emails:
                      with lock: self.log_error(f"{log_prefix}Sending interrupted before sendmail.")
                      return

                 with lock: self.log_error(f"{log_prefix}Sending email...")
                 smtp_conn.sendmail(email, [recipient_email], message.encode('utf-8')) # Encode message
                 with lock: self.log_error(f"{log_prefix}Status: Good - Email sent successfully.")

        except smtplib.SMTPAuthenticationError as e:
            auth_error_msg = f"{log_prefix}Error: Authentication failed. {e}"
            # Check specific error codes/messages if available in 'e'
            if "Application-specific password required" in str(e) or "534-5.7.9" in str(e): # Google's code
                auth_error_msg = f"{log_prefix}Error: Application-specific password required."
            elif "Username and Password not accepted" in str(e) or "535-5.7.8" in str(e): # Google's code
                 auth_error_msg = f"{log_prefix}Error: Wrong username or password."
            # Add checks for other providers if needed (e.g., Microsoft codes)
            with lock:
                self.log_error(auth_error_msg)
        except smtplib.SMTPConnectError as e:
            with lock:
                self.log_error(f"{log_prefix}Error: Connection failed. Could not connect to {smtp_server}:{smtp_port}. {e}")
        except smtplib.SMTPServerDisconnected:
             with lock:
                self.log_error(f"{log_prefix}Error: Server disconnected unexpectedly.")
        except smtplib.SMTPRecipientsRefused as e:
              with lock:
                 self.log_error(f"{log_prefix}Error: Recipient refused by server. Check '{recipient_email}'. {e}")
        except smtplib.SMTPSenderRefused as e:
             with lock:
                self.log_error(f"{log_prefix}Error: Sender '{email}' refused by server. (Check sender policies/permissions). {e}")
        except ConnectionRefusedError:
             with lock:
                 self.log_error(f"{log_prefix}Error: Connection actively refused by the server {smtp_server}:{smtp_port}.")
        except OSError as e: # Catch socket errors, timeouts
              if "timed out" in str(e).lower():
                   with lock: self.log_error(f"{log_prefix}Error: Connection timed out to {smtp_server}:{smtp_port}.")
              else:
                   with lock: self.log_error(f"{log_prefix}Error: Network/OS error. {e}")
        except Exception as e:
            # Catch-all for other unexpected errors during the process
            with lock:
                self.log_error(f"{log_prefix}Error: An unexpected error occurred: {type(e).__name__} - {e}")
            logging.error(f"Unexpected SMTP error for {email}:", exc_info=True) # Log full traceback


    def interrupt_send(self):
        """Sets the flag to stop sending emails."""
        if not self.stop_sending_emails:
            self.stop_sending_emails = True
            self.log_error(">>> Interruption signal received. Stopping new email attempts... <<<")
            self.interrupt_send_btn.setEnabled(False) # Disable after clicking


    def clear_errors(self):
        """Clears the SMTP log display and resets the output files."""
        self.error_text.clear()
        log_dir = os.path.join(os.getcwd(), "SMTP_Logs")
        files_to_clear = [
            'Good.txt', 'App_Password_Required.txt', 'Wrong_Username_Password.txt',
            'Bad.txt', 'Other_Errors.txt'
        ]
        cleared_count = 0
        failed_clear = []
        if os.path.exists(log_dir):
            for filename in files_to_clear:
                filepath = os.path.join(log_dir, filename)
                if os.path.exists(filepath):
                    try:
                        with open(filepath, 'w') as f: # Open in write mode to truncate
                            pass
                        cleared_count += 1
                    except Exception as e:
                        failed_clear.append(filename)
                        logging.error(f"Failed to clear SMTP log file {filepath}: {e}")

        self.log_error("SMTP Log display cleared.")
        if cleared_count > 0:
             self.log_error(f"Cleared {cleared_count} SMTP log files in '{log_dir}'.")
        if failed_clear:
             self.log_error(f"Failed to clear log files: {', '.join(failed_clear)}")
             QMessageBox.warning(self, "Clear Warning", f"Could not clear some log files: {', '.join(failed_clear)}")


    def closeEvent(self, event):
        # Log to self.error_text as it's a general app log location now
        self.log_message("Application closing. Cleaning up...", self.error_text)
        self.close_driver()
        if hasattr(self, 'auto_refresh_timer'): # Stop timer
            self.auto_refresh_timer.stop()
            logging.info("Auto-refresh timer stopped.")
        logging.info("Application shutdown complete.")
        event.accept()


# -------------------------
# Main Execution (Keep as is)
# -------------------------
if __name__ == '__main__':
    logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info("Application starting...")

    app = QApplication(sys.argv)
    app.setApplicationName("GBot V8")
    app.setOrganizationName("YourOrg")
    app.main_window_ref = None # Initialize ref, MainWindow will set it

    initialize_accounts() # Populates global ACCOUNTS, _last_accounts_mtime, etc.
    logging.info(f"Account initialization complete. Found {len(ACCOUNTS)} account(s). Last mtime: {_last_accounts_mtime}, Path: {_last_loaded_accounts_path}")

    main_window = MainWindow() # MainWindow __init__ now sets app.main_window_ref
    main_window.show()

    sys.exit(app.exec_())