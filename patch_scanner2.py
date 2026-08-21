def patch_file():
    with open('src/pages/Scanner.jsx', 'r') as f:
        content = f.read()

    # Remove handleSaveScan entirely
    import re
    # Find handleSaveScan = async () => { ... };
    start = content.find("const handleSaveScan = async () => {")
    if start != -1:
        end = content.find("};", start)
        end = content.find("};", end + 2) # inner try catch has }; maybe?
        # Actually it's better to just do regex or text replacement
        # Let's just find the exact block since it's known
        pass

    # A simpler way:
    # Just remove the props from ReportHeader, and the saveStatus state.
    
    content = content.replace("const [saveStatus, setSaveStatus] = useState('');", "")
    content = content.replace("const [savedScanId, setSavedScanId] = useState(null);", "")
    
    # Remove it from ReportHeader
    content = content.replace("onSaveScan={handleSaveScan}\n", "")
    content = content.replace("savedScanId={savedScanId}\n", "")
    content = content.replace("saveStatus={saveStatus}\n", "")

    # For handleSaveScan, we can just replace its definition with empty if it's there
    content = re.sub(r'const handleSaveScan = async \(\) => \{.*?\n  \};\n', '', content, flags=re.DOTALL)
    
    # Also update Guest 3/3 copy
    old_guest_copy = '''setErrorMessage(
        "You've used your 3 free Guest scans for this week.\\n\\n" +
        "Create a free account to unlock Advanced Scan, get 5 scans every week, save reports, download PDF reports, and access your scan history."
      );'''
    new_guest_copy = '''setErrorMessage(
        "You've used your 3 free Guest scans for this week.\\n\\n" +
        "Create a free account to unlock Advanced Scan, get 5 scans every week, download PDF reports, and access your scan history."
      );'''
    content = content.replace(old_guest_copy, new_guest_copy)
    
    with open('src/pages/Scanner.jsx', 'w') as f:
        f.write(content)

patch_file()
