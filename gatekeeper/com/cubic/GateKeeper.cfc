<cfcomponent name="GateKeeper" output="false" hint="Performs various checks against an ip address, user agent and uri requested, recommending a blocking action if one or more tests are failed">
	<cfset variables.configPath = "/GateKeeper/config/"> <!--- path to gatekeeper configuration files --->
	<cfset variables.logLevel = "POSITIVE"> <!--- POSITIVE | VERBOSE --->
	<cfset variables.honeyPotCacheType = "DATABASE"> <!--- DATABASE | MEMORY --->
	<cfset variables.dsn = "GateKeeper"> <!--- dsn for database cache --->
	<cfset variables.doHoneyPot = true> <!--- set to false to bypass honeypot tests --->
	<cfset variables.hpKey = "<put your honeypot key in here>">
	<cfset variables.honeyPotHTTP = "dnsbl.httpbl.org">
	<cfset variables.honeyPotTypeThreshold = 1>
	<cfset variables.honeyPotThreatThreshold = 10>
	<cfset variables.honeyPotCache = structNew()> <!--- memory cache struct --->
	<cfset variables.honeyPotCacheLength = 60 * 60 * 24> <!--- 24 hours --->


	<!--- ============================================= --->
	<!--- CONSTRUCTOR --->
	<!--- ========================= --->
	<cffunction name="init" access="public" output="false" returnType="any" hint="constructor">
		<cfreturn this>
	</cffunction>
	
	
	<!--- ============================================= --->
	<!--- PUBLIC METHODS --->
	<!--- ========================= --->

	<!--- ========================= --->
	<cffunction name="setHoneyPotKey" output="false" returntype="void" hint="sets our honeypot key">
		<cfargument name="key" required="true" type="string" hint="honey pot API key">
		<cfset variables.hpKey = arguments.key>
	</cffunction>

	<!--- ========================= --->
	<cffunction name="setDoHoneyPot" output="false" returntype="void" hint="set to false to bypass the project honeypot test">
		<cfargument name="do" required="true" type="boolean" hint="true to use the honey pot test, false to bypass">
		<cfset variables.doHoneyPot = arguments.do>
	</cffunction>

	<!--- ========================= --->
	<cffunction name="getHPCache" output="false" returntype="struct" hint="returns our local honey pot cache">
		<cfreturn variables.honeyPotCache>
	</cffunction>

	<!--- ========================= --->
	<cffunction name="clearSession" output="false" returntype="void" hint="clears our session scoped variables">
		<cfif isSessionAvailable()>
			<cflock scope="Session" type="exclusive" timeout="5">
				<cfset structDelete(session, "GateKeeper_ipResult")>
			</cflock>
		</cfif>
	</cffunction>
	
	<!--- ========================= --->
	<cffunction name="test" output="false" returntype="struct" hint="performs our gatekeeper tests">
		<cfargument name="ip" default="#cgi.REMOTE_HOST#" required="false" type="string" hint="IP address to test">
		<cfargument name="ua" default="#cgi.HTTP_USER_AGENT#" required="false" type="string" hint="user agent to test">
		<cfargument name="uri" default="#cgi.SCRIPT_NAME#?#cgi.QUERY_STRING#" required="false" type="string" hint="the uri that has been requested">
		<cfargument name="doTestIP" required="false" default="true" type="boolean">
		<cfargument name="doTestUA" required="false" default="true" type="boolean">
		<cfargument name="doTestURI" required="false" default="true" type="boolean">
		<cfargument name="logLevel" required="false" default="#variables.logLevel#" type="string">
		

		<cfset var local = structNew()>

		<!--- determine our path if we have not been passed one --->
		<cfif NOT len(arguments.uri)>
			<cfset arguments.uri = getPath()>
		</cfif>

		<!--- build our return object --->
		<cfset local.result = structNew()>
		<cfset local.result.ip = arguments.ip>
		<cfset local.result.ua = arguments.ua>
		<cfset local.result.uri = arguments.uri>
		<cfset local.result.block = false>
		<cfset local.result.reason = arrayNew(1)>

		<!--- validate against our whitelist first --->
		<cfif NOT testWhitelist(arguments.ip)>
			<!--- perform our IP Address test --->
			<cfif arguments.doTestIP>
				<cfset local.result.ipTest = testIP(arguments.ip)>
				<cfif local.result.ipTest.block>
					<cfset local.result.block = true>
					<cfset arrayAppend(local.result.reason, local.result.ipTest.reason)>
				</cfif>
			</cfif>

			<!--- perform out UA test --->
			<cfif arguments.doTestUA>
				<cfset local.result.uaTest = testUA(arguments.ua)>
				<cfif local.result.uaTest.block>
					<cfset local.result.block = true>
					<cfset arrayAppend(local.result.reason, local.result.uaTest.reason)>
				</cfif>
			</cfif>

			<!--- perform our URI tests --->
			<cfif arguments.doTestURI>
				<cfset local.result.uriTest = testURI(arguments.uri)>
				<cfif local.result.uriTest.block>
					<cfset local.result.block = true>
					<cfset arrayAppend(local.result.reason, local.result.uriTest.reason)>
				</cfif>
			</cfif>
		</cfif>

		<cfset local.result.reason = arrayToList(local.result.reason, ", ")>

		<!--- log a positive result --->
		<cfif local.result.block OR (arguments.logLevel IS "VERBOSE")>
			<cfset logResult(local.result)>
		</cfif>

		<cfreturn local.result>
	</cffunction>

	<!--- ========================= --->
	<cffunction name="testWhitelist" output="false" returntype="boolean" hint="performs our gatekeeper whitelist IP address test">
		<cfargument name="ip" required="true" type="string" hint="IP address to test">
		
		<cfset var local = structNew()>

		<!--- get our useragent tests --->
		<cfset local.aTests = readConfig("IPWhitelist")>

		<cfloop array="#local.aTests#" index="local.test">
			<cfif len(local.test)>
				<cfif left(local.test, 1) IS "=">
					<cfif arguments.ip IS mid(local.test, 2, len(local.test))>
						<!--- ip is matched to our whitelist --->
						<cfreturn true>
					</cfif>
				<cfelseif reFindNoCase(local.test, arguments.ip)>
					<!--- ip is matched to our whitelist --->
					<cfreturn true>
				</cfif>
			</cfif>
		</cfloop>

		<!--- ip is not in our whitelist --->
		<cfreturn false>
	</cffunction>

	<!--- ========================= --->
	<cffunction name="testIP" output="false" returntype="struct" hint="performs our gatekeeper IP address test">
		<cfargument name="ip" required="true" type="string" hint="IP address to test">
		
		<cfset var local = structNew()>
		<cfset local.result = structNew()>
		<cfset local.result.block = false>
		<cfset local.result.reason = "">


		<!--- check for session caching of this test --->
		<cfif isSessionAvailable()>
			<cfset local.isSessionCached = false>
			<cflock scope="Session" type="readonly" timeout="5">
				<cfif structKeyExists(session, "GateKeeper_ipResult")>
					<cfset local.result = duplicate(session.GateKeeper_ipResult)>
					<cfset local.isSessionCached = true>
				</cfif>
			</cflock>
			<cfif local.isSessionCached>
				<cfreturn local.result>	
			</cfif>
		</cfif>


		<!--- get our useragent tests --->
		<cfset local.aTests = readConfig("IPBlacklist")>

		<cfloop array="#local.aTests#" index="local.test">
			<cfif len(local.test)>
				<cfif left(local.test, 1) IS "=">
					<cfif arguments.ip IS mid(local.test, 2, len(local.test))>
						<cfset local.result.block = true>
						<cfset local.result.reason = "Matched ip blacklist on #local.test#">
						<cfbreak>
					</cfif>
				<cfelseif reFindNoCase(local.test, arguments.ip)>
					<cfset local.result.block = true>
					<cfset local.result.reason = "Matched ip blacklist on #local.test#">
					<cfbreak>
				</cfif>
			</cfif>
		</cfloop>

		<!--- only turn to project honey pot if we have not got a blacklisted IP --->
		<cfif NOT local.result.block AND variables.doHoneyPot AND len(variables.hpKey)>
			<cfset local.result.hp = honeyPotCheck(arguments.ip)>
			<!--- check against our configured honey pot thresholds --->
			<cfif (local.result.hp.threat GTE variables.honeyPotThreatThreshold)
				AND (local.result.hp.type GTE variables.honeyPotTypeThreshold)>
				<cfset local.result.block = true>
				<cfset local.result.reason = "Positive honey pot result">
			</cfif>
		</cfif>


		<!--- save result to session --->
		<cfif isSessionAvailable()>
			<cflock scope="Session" type="exclusive" timeout="5">
				<cfset session.GateKeeper_ipResult = local.result>
			</cflock>
		</cfif>


		<cfreturn local.result>
	</cffunction>

	<!--- ========================= --->
	<cffunction name="testUA" output="false" returntype="any" hint="performs our gatekeeper User Agent test">
		<cfargument name="ua" required="true" type="string" hint="user agent to test">
		<cfset var local = structNew()>
		<cfset local.result = structNew()>
		<cfset local.result.block = false>
		<cfset local.result.reason = "">

		<!--- check for an empty user agent --->
		<cfif NOT len(arguments.ua)>
			<cfset local.result.block = true>
			<cfset local.result.reason = "Empty user agent">
			<cfreturn local.result>
		</cfif>

		<!--- get our useragent tests --->
		<cfset local.aTests = readConfig("userAgents")>

		<cfloop array="#local.aTests#" index="local.test">
			<cfif len(local.test) AND reFindNoCase(local.test, arguments.ua)>
				<cfset local.result.block = true>
				<cfset local.result.reason = "Matched user agent on #local.test#">
				<cfbreak>
			</cfif>
		</cfloop>

		<cfreturn local.result>
	</cffunction>
	
	<!--- ========================= --->
	<cffunction name="testURI" output="false" returntype="any" hint="performs our gatekeeper URI test">
		<cfargument name="uri" required="true" type="string" hint="uri to test">
		<cfset var local = structNew()>
		<cfset local.result = structNew()>
		<cfset local.result.block = false>
		<cfset local.result.reason = "">

		<!--- get our useragent tests --->
		<cfset local.aTests = readConfig("pathTests")>

		<cfloop array="#local.aTests#" index="local.test">
			<cfif len(local.test) AND reFindNoCase(local.test, arguments.uri)>
				<cfset local.result.block = true>
				<cfset local.result.reason = "Matched uri on #local.test#">
				<cfbreak>
			</cfif>
		</cfloop>

		<cfreturn local.result>
	</cffunction>

	
	<!--- ========================= --->
	<cffunction name="purgeDBCache" output="false" returntype="void" hint="clears all expired database cached honey pot results">
		<cfquery name="local.qCache" datasource="#variables.dsn#">
			DELETE FROM tbl_honeyPot
			WHERE expires < <cfqueryparam value="#now()#" cfsqltype="cf_sql_timestamp">
		</cfquery>
	</cffunction>

	<!--- ============================================= --->
	<!--- PRIVATE METHODS --->
	<!--- ========================= --->


	<!--- ========================= --->
	<cffunction name="honeyPotCheck" access="private" output="false" returntype="struct" hint="Check Project HoneyPot http:BL">
		<cfargument name="ip" required="true" type="string">
		<cfset var local = structNew()>
		
		<cfset local.stRet = structNew()>

		<!--- check our cache first --->
		<cfset local.cached = getHoneyPotCache(arguments.ip)>
		<cfif isStruct(local.cached)>
			<cfreturn local.cached>
		</cfif>

		<!--- Get the different IP values --->
		<cfset local.aVal = listToArray(getHostAddress("#variables.hpKey#.#reverseIP(arguments.ip)#.#variables.honeyPotHTTP#"),".")>

		<cfif local.aVal[1] IS "IP-Address not known">
			<!--- set a value indicating ok address --->
			<cfset local.stRet = {
				type=-1,
				threat=0,
				days=0,
				message="IP-Address not known"
			}>
		<cfelse>
			<!--- there was a match so set the return values --->
			<cfset local.stRet.days = local.aVal[2]>
			<cfset local.stRet.threat = local.aVal[3]>
			<cfset local.stRet.type = local.aVal[4]>

			<!--- Get the HP info message ie: threat level --->
			<cfswitch expression="#local.aVal[4]#">
				<cfcase value="0"><cfset local.stRet.message = "Search Engine (0)"></cfcase>
				<cfcase value="1"><cfset local.stRet.message = "Suspicious (1)"></cfcase>
				<cfcase value="2"><cfset local.stRet.message = "Harvester (2)"></cfcase>
				<cfcase value="3"><cfset local.stRet.message = "Suspicious & Harvester (1+2)"></cfcase>
				<cfcase value="4"><cfset local.stRet.message = "Comment Spammer (4)"></cfcase>
				<cfcase value="5"><cfset local.stRet.message = "Suspicious & Comment Spammer (1+4)"></cfcase>
				<cfcase value="6"><cfset local.stRet.message = "Harvester & Comment Spammer (2+4)"></cfcase>
				<cfcase value="7"><cfset local.stRet.message = "Suspicious & Harvester & Comment Spammer (1+2+4)"></cfcase>
			</cfswitch> 

		</cfif>

		<!--- cache our result --->
		<cfset saveToHoneyPotCache(arguments.ip, local.stRet)>

		<cfreturn local.stRet>
	</cffunction>

	<!--- ========================= --->
	<cffunction name="getHostAddress" access="private" output="false" returntype="string" hint="I do the dns lookup against the http:bl servers">
		<cfargument name="host" required="true" type="string">
		<cfset var local = structNew()>
				
		<cftry>
			<!--- jb: added error handling as error is thrown if host
			lookup has no match in http:BL ie: it's not been reported as a problem --->
			<!--- Init class --->
			<cfset local.obj = CreateObject("java", "java.net.InetAddress")>
			<cfset local.result = local.obj.getByName(arguments.host).getHostAddress() >
			<cfcatch type="any">
				<!--- an "error" in this case is an unknown address, which means it is not reported to http:BL --->
				<cfset local.result="IP-Address not known">
			</cfcatch>
		</cftry>
		<!--- Return result --->
		<cfreturn local.result>
	</cffunction>

	<!--- ========================= --->
	<cffunction name="reverseIP" access="private" output="false" returntype="string" hint=" I return IP in reverse format as required by http:BL api" >
		<cfargument name="ip" required="true" type="string">
		<cfset var local = structNew()>
		<cfset local.aIp = listToArray(arguments.ip,".")>
		<!--- Return IP reversed --->
		<cfreturn local.aIp[4] & "." & local.aIp[3] & "." & local.aIp[2] & "." & local.aIp[1]>
	</cffunction>

	<!--- ========================= --->
	<cffunction name="getHoneyPotCache" access="private" output="false" returntype="any" hint="searches the honeypot cache for a given IP">
		<cfargument name="ip" required="true" type="string">
		<cfset var local = structNew()>

		<cfif variables.honeyPotCacheType IS "DATABASE">
			<!--- use database cache --->
			<cfquery name="local.qCache" datasource="#variables.dsn#">
				SELECT TOP 1 honeyPot_id, ip, expires, days, message, threat, type
				FROM tbl_honeyPot
				WHERE ip = <cfqueryparam value="#arguments.ip#" cfsqltype="cf_sql_varchar">
				ORDER BY expires DESC
			</cfquery>

			<!--- do we have a cached record that has not yet expired --->
			<cfif local.qCache.recordCount AND (local.qCache.expires GT now())>
				<cfset local.result = structNew()>
				<cfset local.result.days = local.qCache.days>
				<cfset local.result.message = local.qCache.message>
				<cfset local.result.threat = local.qCache.threat>
				<cfset local.result.type = local.qCache.type>
				<cfset local.result.cached = true>
				<cfreturn local.result>
			</cfif>

		<cfelse>
			<!--- use memory cache --->
			<cfif structKeyExists(variables.honeyPotCache, arguments.ip)>
				<cfset local.result = variables.honeyPotCache[arguments.ip]>
				<!--- check our cached data timestamp against our cache length --->
				<cfif local.result.expires GT now()>
					<!--- cached value is still valid --->
					<cfset local.result.cached = true>
					<cfreturn local.result>
				</cfif>
			</cfif>
		</cfif>

		<cfreturn false>
	</cffunction>

	<!--- ========================= --->
	<cffunction name="saveToHoneyPotCache" access="private" output="false" returntype="void" hint="saves a honeypot result to our local cache">
		<cfargument name="ip" required="true" type="string">
		<cfargument name="result" required="true" type="struct">
		<cfset var local = structNew()>

		<cfset arguments.result.expires = dateAdd("s", variables.honeyPotCacheLength, now())>

		<cfif variables.honeyPotCacheType IS "DATABASE">
			<cfquery name="local.qSave" datasource="#variables.dsn#">
				INSERT INTO tbl_honeyPot (ip, days, message, threat, type, expires)
				VALUES (
					<cfqueryparam value="#left(arguments.ip, 20)#" cfsqltype="cf_sql_varchar">,
					<cfqueryparam value="#val(arguments.result.days)#" cfsqltype="cf_sql_int">,
					<cfqueryparam value="#left(arguments.result.message, 150)#" cfsqltype="cf_sql_varchar">,
					<cfqueryparam value="#val(arguments.result.threat)#" cfsqltype="cf_sql_int">,
					<cfqueryparam value="#val(arguments.result.type)#" cfsqltype="cf_sql_int">,
					<cfqueryparam value="#arguments.result.expires#" cfsqltype="cf_sql_timestamp">
				)
			</cfquery>
		<cfelse>
			<cfset variables.honeyPotCache[arguments.ip] = arguments.result>
		</cfif>
	</cffunction>

	<!--- ========================= --->
	<cffunction name="readConfig" access="private" output="false" returntype="array" hint="reads a confige file and parses the lines into an array" >
		<cfargument name="name" required="true" type="string">
		<cfset var local = structNew()>
		<cfset local.path = expandPath("#variables.configPath##arguments.name#.cfm")>
		<cftry>
			<!--- <cfsavecontent variable="local.tests"><cfinclude template="#variables.configPath##arguments.name#.cfm"></cfsavecontent> --->
			<cflock name="GateKeeper-#arguments.name#" timeout="2">
				<cffile action="read" file="#local.path#" variable="local.tests">
			</cflock>
			<cfreturn listToArray(trim(local.tests), chr(13) & chr(10))>	
			<cfcatch>
				<cfreturn arrayNew(1)>
			</cfcatch>
		</cftry>
	</cffunction>

	<!--- ========================= --->
	<cffunction name="logResult" access="private" output="false" returntype="void" hint="logs a result">
		<cfargument name="result" required="true" type="struct">
		<cfset var local = structNew()>
		<cfset local.logText = "IP: #arguments.result.IP#, UA: #arguments.result.UA#, URI: #arguments.result.URI#, BLOCK:#arguments.result.BLOCK#, REASON: #arguments.result.REASON#">
		<cflog text="#local.logText#" file="GateKeeper">


		<!--- log to database --->
		<cfquery name="local.qSave" datasource="#variables.dsn#">
			INSERT INTO tbl_log (ip, userAgent, domain, path, block, reason, gatekeeperResult)
			VALUES (
				<cfqueryparam value="#left(arguments.result.ip, 20)#" cfsqltype="cf_sql_varchar">,
				<cfqueryparam value="#left(arguments.result.ua, 200)#" cfsqltype="cf_sql_varchar">,
				<cfqueryparam value="#left(cgi.HTTP_HOST, 200)#" cfsqltype="cf_sql_varchar">,
				<cfqueryparam value="#left(arguments.result.uri, 500)#" cfsqltype="cf_sql_varchar">,
				<cfqueryparam value="#arguments.result.block#" cfsqltype="cf_sql_bit">,
				<cfqueryparam value="#arguments.result.reason#" cfsqltype="cf_sql_clob">,
				<cfqueryparam value="#serializeJSON(arguments.result)#" cfsqltype="cf_sql_clob">
			)
		</cfquery>
	</cffunction>
	
	<!--- ============================== --->
	<cffunction name="isSessionAvailable" access="private" output="false" returnType="boolean" hint="determines wether or not the application has session enabled">
		<cfreturn application.GetApplicationSettings().SessionManagement>
	</cffunction>

	<!--- ============================== --->
	<cffunction name="getPath" access="private" output="false" returnType="string" hint="determines the path of the current request">
		<cfset var local = structNew()>
		<cfset local.currentPage = cgi.PATH_INFO>
		<cfif len(cgi.QUERY_STRING)>
			<cfset local.currentPage = local.currentPage & "?" & cgi.QUERY_STRING>
		</cfif>
		<cfreturn local.currentPage>
	</cffunction>
</cfcomponent>