

<cftry>
	
	<!--- make sure that we have a gatekeeper component --->
	<cfif NOT isDefined("application.GateKeeper")>
		<cflock scope="Application" type="exclusive" timeout="5">
			<cfset application.GateKeeper = createObject("component", "GateKeeper.com.cubic.GateKeeper").init()>
		</cflock>
	</cfif>

	<!--- perform our gatekeeper test --->
	<cfset variables.result = application.gatekeeper.test()>
	<cfif variables.result.block>
		<cfheader statuscode="403" statustext="Forbidden">
		<cfabort>
	</cfif>


	<cfcatch>
		<!--- we let any error pass unnoticed --->
	</cfcatch>
</cftry>