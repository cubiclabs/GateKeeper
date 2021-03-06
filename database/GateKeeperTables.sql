USE [GateKeeper]
GO
/****** Object:  Table [dbo].[tbl_log]    Script Date: 02/27/2014 14:08:51 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[tbl_log](
	[log_id] [int] IDENTITY(1,1) NOT NULL,
	[ip] [varchar](20) NOT NULL,
	[userAgent] [varchar](200) NOT NULL,
	[domain] [varchar](200) NOT NULL,
	[path] [varchar](500) NOT NULL,
	[block] [bit] NOT NULL,
	[reason] [varchar](max) NOT NULL,
	[gatekeeperResult] [varchar](max) NOT NULL,
	[timestamp] [datetime] NOT NULL,
 CONSTRAINT [PK_tbl_log] PRIMARY KEY CLUSTERED 
(
	[log_id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[tbl_honeyPot]    Script Date: 02/27/2014 14:08:51 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[tbl_honeyPot](
	[honeyPot_id] [int] IDENTITY(1,1) NOT NULL,
	[ip] [varchar](20) NOT NULL,
	[expires] [datetime] NOT NULL,
	[days] [int] NOT NULL,
	[message] [varchar](150) NOT NULL,
	[threat] [int] NOT NULL,
	[type] [int] NOT NULL,
 CONSTRAINT [PK_tbl_honeyPot] PRIMARY KEY CLUSTERED 
(
	[honeyPot_id] ASC
)WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
SET ANSI_PADDING OFF
GO
/****** Object:  Default [DF_tbl_log_timestamp]    Script Date: 02/27/2014 14:08:51 ******/
ALTER TABLE [dbo].[tbl_log] ADD  CONSTRAINT [DF_tbl_log_timestamp]  DEFAULT (getdate()) FOR [timestamp]
GO
