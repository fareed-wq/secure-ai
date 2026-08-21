def patch_file():
    with open('src/pages/Scanner.jsx', 'r') as f:
        content = f.read()

    # Add savedScanId state
    content = content.replace("const [saveStatus, setSaveStatus] = useState('');", "const [saveStatus, setSaveStatus] = useState('');\n  const [savedScanId, setSavedScanId] = useState(null);")

    # Clear savedScanId on reset
    content = content.replace("setSaveStatus('');", "setSaveStatus('');\n    setSavedScanId(null);")

    # Update handleSaveScan
    old_save = """  const handleSaveScan = async () => {
    if (!user) {
      handleRequireAuth('save reports to your dashboard');
      return;
    }
    
    setSaveStatus('saving');
    try {
      const { error } = await supabase.from('scans').insert([{
        user_id: user.id,
        target_url: reportData.url,
        score: reportData.score || 0,
        report_data: reportData
      }]);
      
      if (error) {
        console.error("Failed to save scan:", error);
        setSaveStatus('error');
      } else {
        setSaveStatus('saved');
        setTimeout(() => setSaveStatus(''), 3000);
      }
    } catch (error) {
      console.error("Failed to save scan:", error);
      setSaveStatus('error');
    }
  };"""

    new_save = """  const handleSaveScan = async () => {
    if (!user) {
      handleRequireAuth('save reports to your dashboard');
      return null;
    }
    
    if (savedScanId) {
        return savedScanId;
    }
    
    setSaveStatus('saving');
    try {
      const { data, error } = await supabase.from('scans').insert([{
        user_id: user.id,
        target_url: reportData.url,
        score: reportData.score || 0,
        report_data: reportData
      }]).select();
      
      if (error) {
        console.error("Failed to save scan:", error);
        setSaveStatus('error');
        return null;
      } else if (data && data.length > 0) {
        const newId = data[0].id;
        setSavedScanId(newId);
        setSaveStatus('saved');
        setTimeout(() => setSaveStatus(''), 3000);
        return newId;
      }
    } catch (error) {
      console.error("Failed to save scan:", error);
      setSaveStatus('error');
      return null;
    }
  };"""

    content = content.replace(old_save, new_save)
    
    # Pass savedScanId to ReportHeader
    content = content.replace("onSaveScan={handleSaveScan}", "onSaveScan={handleSaveScan}\n                savedScanId={savedScanId}")

    with open('src/pages/Scanner.jsx', 'w') as f:
        f.write(content)

patch_file()
