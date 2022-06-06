
#
# This file is part of the PoCs for various issues found in the cryptographic
# design of Mega.
#
# Content: victim automated with Selenium, using the webclient
#

from os.path import basename
from getpass import getpass
from multiprocessing import Process
from time import sleep
from signal import signal, SIGINT, SIGTERM

from shared.constants.mega_web import *
from shared.constants.mitmproxy import *
from shared.constants.victim import *

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.common.exceptions import TimeoutException
    from selenium.webdriver.support import expected_conditions as EC
except ModuleNotFoundError:
    print("Missing dependency: 'selenium', aborting")
    exit(1)


class Victim:
    def __init__(self, uname, mitmproxy_addr=MITMPROXY_ADDR):
        """
        By default, the victim sets up a MitM proxy, set mitmproxy_addr to None
        to get a normal browser.
        """
        # Setup mitmprox for victim
        self.uname = uname
        self.pw = getpass(f"Enter password for user {uname}: ")
        self.driver = None
        self.setup_driver(mitmproxy_addr)
        self.proc = None

    def _wait_for(self, selector, err=""):
        try:
            WebDriverWait(self.driver, 30).until(
                EC.visibility_of_element_located(selector)
            )
        except TimeoutException:
            print(err)
            self.exit()
            return False
        return True

    def setup_driver(self, mitmproxy_addr):
        if self.driver:
            self.driver.quit()

        if mitmproxy_addr:
            firefox_caps = webdriver.DesiredCapabilities.FIREFOX
            firefox_caps["marionette"] = True

            firefox_caps["proxy"] = {
                "proxyType": "MANUAL",
                "httpProxy": mitmproxy_addr,
                "sslProxy": mitmproxy_addr,
            }

            self.driver = webdriver.Firefox(capabilities=firefox_caps)
        else:
            self.driver = webdriver.Firefox()

    def login(self, unsuccessful=False):
        """
        :params unsuccessful: Boolean whether the login is expected to succeed or not

        :returns: False if waiting for an unsuccessful login expired, True otherwise
        """
        self.driver.get(MEGA_LOGIN_PAGE)

        # Wait for login screen
        self._wait_for(
            (By.ID, MEGA_UNAME_FIELD_ID),
            "No invalid session response - terminate login retries"
        )

        # Enter credentials
        uname_field = self.driver.find_element_by_id(MEGA_UNAME_FIELD_ID)
        uname_field.send_keys(self.uname)

        pw_field = self.driver.find_element_by_id(MEGA_PW_FIELD_ID)
        pw_field.send_keys(self.pw)

        login_form = self.driver.find_element_by_id(MEGA_LOGIN_FORM_ID)
        login_button = login_form.find_element(by=By.CLASS_NAME, value=MEGA_LOGIN_FORM_BUTTON_CLASS)
        login_button.click()

        if unsuccessful:
            return not self._wait_for(
                (By.XPATH, MEGA_INV_SESSION_XPATH),
                "Timeout while waiting for invalid session response to login"
            )
        return True

    def loop_unsuccessful_logins(self):
        while True:
            if self.login(unsuccessful=True):
                return
            sleep(MIN_TIME_BETWEEN_LOGINS)

            self._wait_for(
                (By.XPATH, MEGA_INV_SESSION_XPATH),
                "No invalid session response - terminate login retries"
            )

    def loop_unsuccessful_logins_detached(self):
        self.proc = Process(target=self.loop_unsuccessful_logins)
        self.proc.start()

    def logout(self, skip_recovery=False):
        # Show account menu
        top_menu = self.driver.find_element_by_id(MEGA_TOP_MENU_ID)
        avatar_button = \
            top_menu.find_element(by=By.CLASS_NAME, value=MEGA_AVATAR_BUTTON_CLASS)
        avatar_button.click()

        # Click logout
        top_menu = self.driver.find_element_by_id(MEGA_TOP_MENU_ID)
        logout_button = \
            top_menu.find_element(by=By.CLASS_NAME, value=MEGA_LOGOUT_BUTTON_CLASS)
        logout_button.click()

        if skip_recovery:
            self.skip_recovery()

    def skip_recovery(self):
        recovery_skip_button = \
            self.driver.find_element(by=By.CLASS_NAME, value=MEGA_SKIP_BUTTON_CLASS)
        recovery_skip_button.click()

        # Wait until startpage loaded
        self._wait_for(
            (By.CLASS_NAME, MEGA_TOP_LOGIN_BUTTON_CLASS),
            "Timeout while waiting for user cloud to load"
        )

    def wait_for_cloud(self):
        self._wait_for(
            (By.CLASS_NAME, MEGA_CLOUD_BODY_CLASS),
            "Failed to load cloud for user, waiting expired after 30s"
        )

    def open_file_menu(self, fname):
        for file in self.driver.find_elements_by_css_selector(MEGA_FILE_CSS_SELECTOR):
            title = file.find_element(by=By.CLASS_NAME, value=MEGA_FILE_TITLE_CLASS)
            if title.text == basename(fname):
                settings = file.find_element(by=By.CLASS_NAME, value=MEGA_FILE_SETTINGS_CLASS)
                settings.click()

                self._wait_for(
                    (By.CSS_SELECTOR, MEGA_FILES_MENU_INFO_SELECTOR),
                    "Timeout while waiting for file menu"
                )
                break

    def view_in_browser(self, fname):
        # Double click in ActionChains seems buggy, use workaround
        self.open_file_menu(fname)
        preview_item = self.driver.find_element_by_css_selector(
            MEGA_FILE_PREVIEW_CSS_SELECTOR
        )
        preview_item.click()

        self._wait_for(
            (By.CSS_SELECTOR, MEGA_IMG_CSS_SELECTOR),
            "Timeout while waiting for forged image to display"
        )

    def share_file(self, fname, close_share_window=True):
        self.open_file_menu(fname)

        share_item = self.driver.find_element_by_css_selector(
            MEGA_FILE_SHARE_CSS_SELECTOR
        )
        share_item.click()

        self._wait_for(
            (By.CSS_SELECTOR, MEGA_SHARE_LINK_CSS_SELECTOR),
            "Timeout while waiting for share dialog to display"
        )

        share_link_elem = self.driver.find_element_by_css_selector(
            MEGA_SHARE_LINK_CSS_SELECTOR
        )
        share_link = share_link_elem.get_attribute("value")

        # Sleeps to make share link visible to humans
        sleep(2)

        if close_share_window:
            self.close_share_dialog()

        return share_link

    def unshare_file(self, fname):
        self.open_file_menu(fname)

        unshare_item = self.driver.find_element_by_css_selector(
            MEGA_FILE_UNSHARE_CSS_SELECTOR
        )
        unshare_item.click()

        self._wait_for(
            (By.CSS_SELECTOR, MEGA_SHARE_MSG_DIALOG_CONFIRM_CSS_SELECTOR),
            "Timeout while waiting for message dialog"
        )

        confirm_item = self.driver.find_element_by_css_selector(
            MEGA_SHARE_MSG_DIALOG_CONFIRM_CSS_SELECTOR
        )
        confirm_item.click()

        self.wait_for_cloud()
        # Sometime it is slower to load
        sleep(2)

    def close_share_dialog(self):
        share_item = self.driver.find_element_by_css_selector(
            MEGA_SHARE_DIALOG_CLOSE_CSS_SELECTOR
        )
        share_item.click()
        sleep(1)

    def assure_is_alive(self):
        if not self.proc or not self.proc.is_alive():
            msg = "Victim browser process stopped unexpectedly"
            if self.proc:
                msg += f" with return code {self.proc.exitcode}"
            print(msg)
            exit(1)

    def exit(self):
        if self.proc:
            self.proc.terminate()
            self.proc = None
        self.driver.quit()
