# Volatility

## Operating Sytem
### vol3
vol.py -f mem.raw windows.info
### vol2 -f mem.raw imageinfo
```
/// to safe typing...
export VOLATILITY_PROFILE=Win7SP1x64
```





## Shimcache
vol3.py -f mem.raw windows.shimcachemem

## Last Exit: Bulk-Extractor

If nothing is working:

```
brew install bulk_extractor
bulk_extractor -V // App-Check

bulk_extractor -o out mem.raw
```