---
- PROXY
---

CREATE TABLE `BlackList` (
  `BlackListID` int(10) unsigned NOT NULL auto_increment,
  `BlackListHost` varchar(255) NOT NULL default ''
);

CREATE TABLE `Client` (
  `ClientID` int(10) unsigned NOT NULL auto_increment,
  `ClientTS` timestamp NOT NULL default CURRENT_TIMESTAMP,
  `ClientAddedBy` varchar(255) NOT NULL default '',
  `ClientReseller` int(10) unsigned NOT NULL default '0',
  `ClientCustomer` int(10) unsigned NOT NULL default '0',
  `ClientIP` varchar(255) NOT NULL,
  `ClientLabel` varchar(255) NOT NULL default '',
  `ClientFlags` int(10) unsigned NOT NULL default '0'
);

CREATE TABLE `Site` (
  `SiteID` int(10) unsigned NOT NULL auto_increment,
  `SiteTS` timestamp NOT NULL default CURRENT_TIMESTAMP,
  `SiteAddedBy` varchar(255) NOT NULL default '',
  `SiteReseller` int(10) unsigned NOT NULL default '0',
  `SiteCustomer` int(10) unsigned NOT NULL default '0',
  `SiteHost` varchar(255) NOT NULL default '',
  `SiteAction` varchar(255) NOT NULL default '',
  `SiteActionString` varchar(255) NOT NULL default ''
);

---
- PROXYLOG database
---

CREATE TABLE `Log` (
  `LogID` int(10) unsigned NOT NULL auto_increment,
  `LogTS` timestamp NOT NULL default '0000-00-00 00:00:00',
  `LogReseller` int(10) unsigned NOT NULL default '0',
  `LogCustomer` int(10) unsigned NOT NULL default '0',
  `LogSentClient` int(10) unsigned NOT NULL default '0',
  `LogSentServer` int(10) unsigned NOT NULL default '0',
  `LogResult` smallint(5) unsigned NOT NULL default '0',
  `LogHost` varchar(128) NOT NULL default ''
);


---
- CORE database
---

CREATE TABLE `Customer` (
  `CustomerID` int(10) unsigned NOT NULL auto_increment,
  `CustomerName` varchar(255) NOT NULL default '',
  `CustomerType` int(10) unsigned NOT NULL default '0'
);

CREATE TABLE `Reseller` (
  `ResellerID` int(10) unsigned NOT NULL auto_increment,
  `ResellerName` varchar(255) NOT NULL default '',
  `ResellerType` int(10) unsigned NOT NULL default '0'
);
