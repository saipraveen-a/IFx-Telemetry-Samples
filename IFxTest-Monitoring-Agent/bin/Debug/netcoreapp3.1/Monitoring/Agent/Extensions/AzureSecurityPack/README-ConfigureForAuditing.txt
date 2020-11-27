
NOTE: The instructions below should only be used for testing locally. For Prod and Test changes, follow the onboarding guide.

===
For onboarding, please refer to the documentation at:

https://microsoft.sharepoint.com/teams/AzureSecurityCompliance/Security/SitePages/Auditing.aspx

===
Please use the bits as the following with the Azure drop:

1. Reference the following:
	Windows.Azure.Auditing.AuditCommonApi.dll
	Windows.Azure.Auditing.Logging.DataCenterLogging.dll
	Windows.Azure.Auditing.Logging.ETWLogging.dll

2. Add the following to your project as content.  Set the build action to "None" and Copy to Output Directory to "Copy Always"
	AuditEventMessages.dll
	AuditInstaller.cmd
	ConfigureForAuditing.exe
	AuditETWProvider.man

3. In your service definition file add the following as startup task.  If you are starting monitoring agent, start that before this task:
    <Startup>      
      <Task commandLine="AuditInstaller.cmd" executionContext="elevated" taskType="simple"></Task>
    </Startup>    
	
    If you want to pass custom security event log size or if you need to give priviledge to log to security event log
    to an account that your web role or worker role is running under (ACCOUNT_NAME) then pass the parameters as follows
 
    <Startup>      
      <Task commandLine="AuditInstaller.cmd /sizeInMB 100 /accountName ACCOUNT_NAME" executionContext="elevated" taskType="simple"></Task>
    </Startup>    

4. In your mds config file, add the following under events node. (Or merge with EtwProviders node if you already have this node)

   <EtwProviders>
      <EtwProvider guid="648f8286-7880-4169-8098-86da03c4e4ef" format="Manifest" storeType="Central" priority="Normal">
        <DefaultEvent eventName="DefaultLogEvent" />	
      </EtwProvider>
    </EtwProviders>
