
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: constants relevant for the web client (URL, HTML, IDs, etc.)
#

from shared.attack_utils import *

## URLs
MEGA_LOGIN_PAGE = "https://mega.nz/login"

## DOM elements
MEGA_LOGIN_FORM_ID = "login_form"
MEGA_UNAME_FIELD_ID = "login-name2"
MEGA_PW_FIELD_ID = "login-password2"
MEGA_LOGIN_FORM_BUTTON_CLASS = "login-button"

MEGA_TOP_MENU_ID = "topmenu"
MEGA_AVATAR_BUTTON_CLASS = "js-topbaravatar"
MEGA_LOGOUT_BUTTON_CLASS = "logout"
MEGA_SKIP_BUTTON_CLASS = "button-prd-skip"
MEGA_TOP_LOGIN_BUTTON_CLASS = "top-login-button"
MEGA_CLOUD_BODY_CLASS = "fm-blocks-view"
MEGA_FILE_CSS_SELECTOR = "a.file"
MEGA_FILE_TITLE_CLASS = "file-block-title"
MEGA_FILE_SETTINGS_CLASS = "file-settings-icon"
MEGA_FILES_MENU_INFO_SELECTOR = ".files-menu .properties-item"
MEGA_FILE_PREVIEW_CSS_SELECTOR = ".files-menu .preview-item"
MEGA_IMG_CSS_SELECTOR = "#videoContainer .img1"
MEGA_FILE_SHARE_CSS_SELECTOR = ".files-menu .getlink-item"
MEGA_SHARE_LINK_CSS_SELECTOR = ".link input"
MEGA_SHARE_DIALOG_CLOSE_CSS_SELECTOR = ".export-links-dialog .close"
MEGA_FILE_UNSHARE_CSS_SELECTOR = ".files-menu .removelink-item"
MEGA_SHARE_MSG_DIALOG_CONFIRM_CSS_SELECTOR = "#msgDialog .confirm"

## Some storage server of Mega (which one doesn't matter, just avoiding SOP-related issues)
MEGA_STORAGE_SERVER_DOMAIN = "gfs270n070.userstorage.mega.co.nz"
MEGA_STORAGE_SERVER = (
    f"https://{MEGA_STORAGE_SERVER_DOMAIN}/dl/{rand_url_encoding(52)}",
    "89.44.168.211",
    "2001:678:25c:2216::211"
)

## Local file
SHARE_LINK_LOCAL_FNAME = "/tmp/share_link.txt"

## Misc
MEGA_INV_SESSION_XPATH = "//*[contains(text(), 'Login session expired or invalid')]"
