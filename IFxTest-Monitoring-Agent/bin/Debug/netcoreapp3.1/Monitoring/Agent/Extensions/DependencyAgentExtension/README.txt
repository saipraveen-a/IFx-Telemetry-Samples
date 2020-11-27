Release Notes:

Version 1.0.13 
	Support invoking DAextension from directory under system root directory.

This package includes the Dependency Agent installer for Windows and its MA extension in bin directory.  DAExtension.exe manage the installation procedure, 
the CSV files are produced in storage directory under installation directory. 

The DA extension automates the property file settings, not need to manually copy property file as in direct installer invoking scenario below.

Installation scenarios for running installer directly

1. Run installer as following. DA starts after installation, No CSV file is produced
	InstallDependencyAgent-novc-Windows.exe

2. DA does not start after installation. Start after configuration is set
	InstallDependencyAgent-novc-Windows.exe /VME
	copy MicrosoftDependencyAgent.properties to "%Programfiles%\Microsoft Dependency Agent\config
	net start MicrosoftDependencyAgent
	
Configuration examples

The property file in config directory is an example to configure the agent.  After install dependency agent, copy the property file 
to "%Programfiles%\Microsoft Dependency Agent\config with desired values.  Dependency agent will pick up the configuration.  The three lines are used as:

	collector.geneva.enabled = true
	- CSV file generation is enabled, required for all other cofigurations below.
	- if not presents or value is false, no CSV file is created.

	collector.etw.httpsys.enabled = true
	- Dependency agent output HTTP type to CSV file.
	- if not presents or value is false, HTTP type is not available in CSV file.

	protocol.dns.enabled = true
	- Enable DNS record output.

	protocol.tcpdns.enabled = true
	- Enable DNS information shown in network record.

CSV file clean up behavior

A CSV file is deleted at the end of 24-hour period as long as the DA is runing since its creation and not output path change since start, no matter 
where the output path.

If DA is stopped, the CSV files are left in the output location.  Restart allows DA delete all stale
CSV files of previous session.  

 
