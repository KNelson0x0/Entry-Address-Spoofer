<h1 align="Center">Entry Address Spoofer (EAS)</h1>
<br/>
<h3 align="left">About</h3>
<p align="left"> 
 A small POC Virtual Method Table (VMT) hook that makes the entry address appear as if its in the correct (or specified) modules range. 
</p>

<h3 align="left">How</h3>
<p align="left"> 
 EAS writes a small hook somewhere in the modules memory which points to the the function you would like to call instead of the original. EAS looks for small to large sections of aligning bytes or '\xCC's to do this.
</p>

<h3 align="left">Example</h3>
<img src="https://raw.githubusercontent.com/KNelson0x0/Entry-Address-Spoofer/main/Imgs/original.jpg">
<p align="center">The objects unchanged vtable.<p>
<br/>
<img src="https://raw.githubusercontent.com/KNelson0x0/Entry-Address-Spoofer/main/Imgs/No%20EAS.jpg">
<p align="center">A regular VMT hook points directly to the desired function to call. This can be very easily detected as that function is not in the correct modules  address range.<p>
<br/>
<img src="https://raw.githubusercontent.com/KNelson0x0/Entry-Address-Spoofer/main/Imgs/With%20EAS.jpg">
<p align="center">Using EAS the top function on the vtable is in the correct module range. </p>

<h3 align="left">Notes</h3>
<p align="left"> 
> EAS can still easily be detected using integrity checks as it patches the .text section. <br/>
> EAS can be detected if the binary you are working against keeps copies of the proper vtable addresses.<br/>
> If you have the option to just use an inline hook take it. While EAS and inline hooking are both very fast inline hooking is still faster.<br/>
  EAS generates a few extra instructions around the area of memory it replaces with the hook in order to defeat first-byte-jump detection.  <br/>
  This means that EAS will be running a few extra instructions every time the hook is called and while the performance difference is not noticable, 
  in this case one instruction is faster than 5-10.
</p>
