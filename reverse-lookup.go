package main

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type CacheEntry struct {
	hostname string
	expires  time.Time
}
type ReverseLookupCache struct {
	hostnames sync.Map
	keys      []string
	next      int
}

var reverseLookupCache *ReverseLookupCache

func LoadReverseLookupCache() {
	reverseLookupCache = &ReverseLookupCache{
		keys: make([]string, 65536),
	}
	log.Infof("Loaded reverse lookup cache")
}

func (c *ReverseLookupCache) lookup(ipv4 string) string {
	hit, ok := c.hostnames.Load(ipv4)
	if !ok {
		log.Debugf("lookup(): CACHE_MISS")
		return ""
	}
	if hit, ok := hit.(*CacheEntry); ok {
		if hit.expires.After(time.Now()) {
			return hit.hostname
		} else {
			log.Debugf("lookup(): CACHE_EXPIRED")
			c.hostnames.Delete(ipv4)
		}
	}
	return ""
}

func (c *ReverseLookupCache) store(ipv4, hostname string) {
	c.storeTtl(ipv4, hostname, int(time.Hour/time.Second))
}

func (c *ReverseLookupCache) storeTtl(ipv4, hostname string, ttl int) {
	c.hostnames.Delete(c.keys[c.next])
	c.keys[c.next] = ipv4
	c.next = (c.next + 1) & 65535
	c.hostnames.Store(ipv4, &CacheEntry{hostname: hostname, expires: time.Now().Add(time.Duration(ttl) * time.Second)})
}

func ListHostNames() map[string]string {
	c := reverseLookupCache
	m := make(map[string]string)
	c.hostnames.Range(func(ipv4, entry interface{}) bool {
		m[entry.(*CacheEntry).hostname] = ipv4.(string)
		return true
	})
	return m
}

func GetHostName(ip string) string {
	hostname := reverseLookupCache.lookup(ip)
	return hostname
}
