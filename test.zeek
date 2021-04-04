global IPtable :table[addr] of set[string] ;
event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{
local x: set[string];
local uA:string;
	if(hlist[2]$name=="USER-AGENT")
	{
		uA=hlist[2]$value;
		if(c$id$orig_h in IPtable)
		{
			x=IPtable[c$id$orig_h];
			add x[uA];
			IPtable[c$id$orig_h]=x;
		}
    else
		{
			add x[uA];
			IPtable[c$id$orig_h]=x;
		}
	}
}
event zeek_done()
{
local x:addr;
	for(x in IPtable)
	{
		if(|IPtable[x]|>=3)
		{
		print cat(x," is a proxy");
		}
	}
}
