package uk.ac.ravensbourne.casevault.security;

import io.github.bucket4j.Bandwidth; import io.github.bucket4j.Bucket; import java.time.Duration; import java.util.concurrent.*; import org.springframework.stereotype.Service;
/** Limits credential guessing by IP and account before password verification (CWE-307). */
@Service public class LoginRateLimiter { private final ConcurrentMap<String,Bucket> buckets=new ConcurrentHashMap<>(); public boolean allow(String ip,String account){return consume("ip:"+ip,30)&&consume("account:"+account.toLowerCase(),10);} private boolean consume(String key,int capacity){return buckets.computeIfAbsent(key,k->Bucket.builder().addLimit(Bandwidth.builder().capacity(capacity).refillGreedy(capacity,Duration.ofMinutes(1)).build()).build()).tryConsume(1);} }
