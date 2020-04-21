# 404 > 2
# 404response/all respunse > 0.2
# unique url of 404response/404response > 0.5

@load base/frameworks/sumstats

event zeek_init()
{
	local r1 = SumStats::Reducer($stream="404.response", $apply=set(SumStats::SUM));
	local r2 = SumStats::Reducer($stream="allresponse", $apply=set(SumStats::SUM));
	local r3 = SumStats::Reducer($stream="uniqueurl", $apply=set(SumStats::UNIQUE));
	SumStats::create([$name="scanner.detect",
					  $epoch=10mins,
					  $reducers=set(r1, r2, r3),
					  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = 
					  {
						  local s1 = result["404.response"];
						  local s2 = result["allresponse"];
						  local s3 = result["uniqueurl"];
						  if(s1$sum > 2)
						  {
							  if(s1$sum / s2$sum > 0.2)
							  {
								  if(s3$unique / s1$sum > 0.5)
								  {
									  print fmt("%s is a scanner with %d scan attempts on %d urls.", key$host, s1$num, s3$unique);
								  }
							  }
						  }		 
					  }
	]);
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
	if(code == 404)
	{
		SumStats::observe("404.response", [$host=c$id$orig_h], [$num=1]);
		SumStats::observe("uniqueurl", [$host=c$id$orig_h], [$str=c$http$uri]);
	}
	SumStas::observe("allresponse", [$host=c$id$orig_h], [$num=1]);
}
