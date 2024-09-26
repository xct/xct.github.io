---
# the default layout is 'page'
icon: fas fa-tools
order: 4
---

## Labs

- <https://vulnlab.com>

## Shelf

- <https://github.com/xct/winssh>
- <https://github.com/xct/hashgrab>
- <https://github.com/xct/rcat>
- <https://github.com/xct/winpspy>

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

<textarea id="inputToDouble" name="inputToDouble" rows="10" cols="80" placeholder="Example:
0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41.."></textarea>

<form onsubmit="return inputToDouble();" form="jsShellcodeForm">
    <input type="submit" value="Convert">
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

<textarea id="inputFromDouble" name="inputFromDouble" rows="10" cols="80" placeholder="Example:
6.867659397734779e+246
7.806615353364766e+184
.."></textarea>

<form onsubmit="return inputFromDouble();" form="jsDoubleForm">
    <input type="submit" value="Convert">
</form>