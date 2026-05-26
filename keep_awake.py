import sys
from playwright.sync_api import sync_playwright

URL = "https://threatscope-ame8t7utwmtjl8rnyauohb.streamlit.app/"

def main():
    print(f"Starting keep-awake trigger for {URL}...")
    with sync_playwright() as p:
        # Launch headless browser
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        # Navigate to the page
        print("Navigating to URL...")
        response = page.goto(URL, timeout=60000)
        
        # Wait a bit for JS to execute
        page.wait_for_timeout(10000)
        
        print(f"Page Title: {page.title()}")
        print(f"Response Status: {response.status if response else 'No Response'}")
        
        # Look for the wake-up button
        # Streamlit sleeping page has a button like "Yes, get this app back up!"
        wake_up_text_selectors = [
            "text=Yes, get this app back up!",
            "text=get this app back up",
            "button:has-text('get this app back up')",
            "text=Wake up app",
            "button:has-text('Wake up')"
        ]
        
        button_clicked = False
        for selector in wake_up_text_selectors:
            locator = page.locator(selector)
            if locator.count() > 0:
                print(f"Found sleep button using selector: '{selector}'")
                try:
                    locator.click()
                    print("Clicked wake-up button! Waiting 30 seconds for app to wake up...")
                    page.wait_for_timeout(30000)
                    button_clicked = True
                    break
                except Exception as click_err:
                    print(f"Failed to click button with selector '{selector}': {click_err}")
        
        if not button_clicked:
            print("No wake-up button found. The app is likely already awake or loaded.")
            
        # Take a screenshot to verify state (useful for GitHub Actions logs)
        try:
            page.screenshot(path="screenshot.png")
            print("Screenshot saved to screenshot.png")
        except Exception as ss_err:
            print(f"Could not take screenshot: {ss_err}")
            
        browser.close()
        print("Keep-awake execution completed.")

if __name__ == "__main__":
    main()
