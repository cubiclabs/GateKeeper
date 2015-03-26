GateKeeper
==========

Prevent access to your ColdFusion sites by bad robots, suspicious IP addresses and blacklisted paths. We have been running this on a number servers since mid 2013 and it has proven to be very effective at removing unwanted visitors and has reduced the load put on the servers by unwanted robots.

This does not replace good practice in securing your sites or servers and it is not affiliated with Project Honeypot in any way.


Project Honeypot
----------------
> "Project Honey Pot is the first and only distributed system for identifying spammers and the spambots they use to scrape addresses from your website. Using the Project Honey Pot system you can install addresses that are custom-tagged to the time and IP address of a visitor to your site. If one of these addresses begins receiving email we not only can tell that the messages are spam, but also the exact moment when the address was harvested and the IP address that gathered it."
https://www.projecthoneypot.org/

To use the Project Honeypot API (https://www.projecthoneypot.org/httpbl_api.php) you need to create an account and request an access key (https://www.projecthoneypot.org/httpbl_configure.php).

If you find this useful, you may want to consider adding a honeypot onto your site to help with the collection of data.


Setup
----------------
GateKeeper has been built with the idea of protecting multiple sites on a single server. 

Download all the files and put then into a suitable directory on your server.


### CF Mapping
Within your ColdFusion administrator create a 'GateKeeper' mapping that points to the directory that you downloaded the GateKeeper files into.


### Database
You must setup an appropriate database (see the GateKeeperTables.sql file) and have created a suitable DSN in the ColdFusion administrator.

The database is used for logging purposes and can also be used to cache honeypot results.

### Configuration Files

A number of configuration files reside in the 'config' directory.

#### IPWhitelist.cfm
This lets you list ip addresses that you want to grant access to regarless of all the other tests. You can either specify an exact match by prefixing with an `=`. For example:

```
=127.0.0.1
```

Anything entered without the `=` prefix is treated as regular expression.

Separate entries with a new line.

#### IPBlacklist.cfm
This lets you list ip addresses that you want to outright blacklist. You can either specify an exact match by prefixing with an `=`. For example:

```
=192.74.234.70
```

Anything entered without the `=` prefix is treated as regular expression.

Separate entries with a new line.

#### pathTests.cfm

Each line is treated as a regular expression. GateKeeper matches against the script name and query string.

```
(/blockme/(?!allowme\.cfm))
```

#### userAgents.cfm
Each line is treated as a regular expression. GateKeeper matches against the current user agent string.

```
(ezooms|AhrefsBot|abonti|MJ12bot|CompSpyBot|BLEXBot|Synapse)
```

### Configuration Options

There are a number of configuration options within the GateKeeper.cfc. I realise that this is not the best place to define these values, but until I get more time to work on this, this is where they are...

```ColdFusion
<cfset variables.configPath = "/GateKeeper/config/">
```

This is the path to the directory containing the configuration files


```ColdFusion
<cfset variables.logLevel = "POSITIVE">
```
This can be set to be either 'POSITIVE' or 'VERBOSE'.

Setting this to 'POSITIVE' logs only postive results - those which should be blocked. 'VERBOSE' logs every request. 

The log files generated can be viewed via the ColdFusion administrator and are named 'GateKeeper'.



```ColdFusion
<cfset variables.honeyPotCacheType = "DATABASE">
```
This defines where honeypot results are cached. This can be set to be either 'DATABASE' or 'MEMORY'.

If set to 'DATABASE', you must setup an appropriate database (see the SQL Server .bak file) and have created a suitable DSN in the ColdFusion administrator.

If set the 'MEMORY', honeypot results are cached in the application scope.


```ColdFusion
<cfset variables.dsn = "GateKeeper">
```
This is the name of the DSN for the database being used for the honeypot cache and for logging


```ColdFusion
<cfset variables.doHoneyPot = true>
```
Set this to false to bypass the honeypot tests and just use the useragent, ip address blacklist and path checking.


```ColdFusion
<cfset variables.hpKey = "<put your honeypot key in here>">
```
You need to obtain a key from Project Honey Pot to use their service.


```ColdFusion
<cfset variables.honeyPotHTTP = "dnsbl.httpbl.org">
```
This is the Project Honey Pot service address


```ColdFusion
<cfset variables.honeyPotTypeThreshold = 1>
```
Great than or equal to this value for a honey pot 'type' returns a positive result:

* Search Engine (0)
* Suspicious (1)
* Harvester (2)
* Suspicious & Harvester (1+2)
* Comment Spammer (4)
* Suspicious & Comment Spammer (1+4)
* Harvester & Comment Spammer (2+4)
* Suspicious & Harvester & Comment Spammer (1+2+4)

```ColdFusion
<cfset variables.honeyPotThreatThreshold = 10>
```
This is the honey pot threat level. Great than or equal to this returns a positive result.

```ColdFusion
<cfset variables.honeyPotCacheLength = 60 * 60 * 24>
```
This is the length of time to cache a honey pot result for. The default is 24 hours.

### application.cfc

Within the application.cfc of any site that you wish to protect include the gatekeeper stub file as follows:

```ColdFusion
<cffunction	name="OnRequestStart" access="public" returntype="boolean" output="false" hint="Fires at first part of page processing.">
	<cfargument name="TargetPage" type="string" required="true">
		
	<!--- gatekeeper --->
	<cfinclude template="/GateKeeper/inc_gatekeeper.cfm">
</cffunction>
```