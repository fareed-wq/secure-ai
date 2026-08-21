wa = open('src/WhatsAppWidget.jsx').read()

# Container
wa = wa.replace('className="absolute bottom-20 right-0 w-80 bg-white rounded-2xl shadow-2xl overflow-hidden flex flex-col"', 'className="absolute bottom-20 right-0 w-80 rounded-2xl shadow-2xl overflow-hidden flex flex-col whatsapp-container"')

# Header
wa = wa.replace('className="bg-[#25D366] p-4 flex items-center justify-between text-white"', 'className="p-4 flex items-center justify-between text-white whatsapp-header"')

# Body
wa = wa.replace('className="bg-[#E5DDD5] p-5 relative overflow-hidden h-36"', 'className="p-5 relative overflow-hidden h-36 whatsapp-body"')

# Bubble
wa = wa.replace('className="bg-white text-slate-800 p-3 rounded-xl rounded-tl-sm shadow-sm max-w-[85%] relative z-10"', 'className="p-3 rounded-xl rounded-tl-sm shadow-sm max-w-[85%] relative z-10 whatsapp-bubble"')

# Actions
wa = wa.replace('className="p-4 bg-white flex flex-col gap-3"', 'className="p-4 flex flex-col gap-3 whatsapp-actions"')

# Action Button
wa = wa.replace('className="w-full bg-[#25D366] hover:bg-[#20bd5a] text-white font-medium py-3 rounded-full transition-colors flex justify-center items-center gap-2"', 'className="w-full font-medium py-3 rounded-full transition-colors flex justify-center items-center gap-2 whatsapp-btn"')

# Floating Open Button
wa = wa.replace('className="bg-[#25D366] hover:bg-[#20bd5a] text-white p-4 rounded-full shadow-lg flex items-center justify-center transition-colors"', 'className="p-4 rounded-full shadow-lg flex items-center justify-center transition-colors whatsapp-btn"')

# Floating Close Button
wa = wa.replace('className="bg-[#25D366] hover:bg-[#20bd5a] text-white p-3 rounded-full shadow-lg flex items-center justify-center transition-colors absolute bottom-0 right-0"', 'className="p-3 rounded-full shadow-lg flex items-center justify-center transition-colors absolute bottom-0 right-0 whatsapp-btn"')

open('src/WhatsAppWidget.jsx', 'w').write(wa)
