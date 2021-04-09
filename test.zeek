global IPtable :table[addr] of set[string] ;
event http_all_headers(c: connection, is_orig: bool, name: string, value: string)
{
if (to_lower(name)=="user-agent")
	{
		if (c$id$orig_h in IPtable) 
	  {
		  add IPtable[c$id$orig_h][value];
	  }
	  else
	  {
		  IPtable[c$id$orig_h]=set(value);

		}
	}
}
event zeek_done()
{
        for(x in IPtable)
	{
		if(|IPtable[x]|>=3)
		print fmt("%s is a proxy",x);
	}
}
