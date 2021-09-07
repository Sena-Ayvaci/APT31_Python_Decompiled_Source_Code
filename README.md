# APT31_Python_Decompiled_Source_Code
The decompiled Python code is consistent among all the samples. The only change we observed was in the access token. Even the AES encryption key is shared between all the samples.


Recently, Zscaler's ThreatLabZ team discovered several malicious MSI installer binaries that were hosted on attacker-controlled GitHub accounts and distributed in-the-wild in August 2020. These MSI binaries dropped and displayed decoy content using a theme around a COVID-19 vaccine as a social engineering technique.

After further analysis of these MSI binaries, we gathered sufficient intel from the code base and attack flow to correlate it to the Chinese state-sponsored threat actor APT 31. In this blog, we will share details of the attack flow, threat attribution, correlation between various instances of attacks by this threat actor, and an in-depth technical analysis of the payloads involved. We will conclude our analysis by sharing indicators of compromise (IOCs), useful metadata, and the complete decompiled Python script, which was the main payload involved in these attacks.

 
