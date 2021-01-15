Scripts

Things that still have to be done manually:

1) Ensure the scripts complete successfully before starting next script
2) Scripts 1 and 2 should be able to create lab environment for any 70- lab, Script 3 customises for the specific lab. Need to verify for each of the labs. 
2) Rename does not always work
3) Installing RSAT on admin workstation
4) Updates
5) Rename Network Adapters to reflect network connected to.

Issues when run:
1) Automatic admin logon
2) Having to restart script at various stages because could not connect to pssession successfully
3) Sometimes machines do not rename 
4) Windows Updates
5) Multiple adapters for Lab 13 (70-740)
6) Default users
7) Reset Administrator Password
8) Modify default GPO to allow for non-complex passwords
9) Display settings
10) Rename Host based on VM name (i.e. Host on VM LON-SVR1 automatically becomes LON-SVR1)
11) Need to establish a better way to pause - until can establish pssession or 20 minutes or something