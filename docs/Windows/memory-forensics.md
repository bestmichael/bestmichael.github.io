# Volatility

For some issues, vol2 is better that vol3, so please be open for both.

## Operating Sytem
```
vol3.py -f mem.raw windows.info        

vol2.py -f mem.raw imageinfo
/// to safe typing...
export VOLATILITY_PROFILE=Win7SP1x64
export VOLATILITY_LOCATION=img.raw
```


## Shimcache
```
vol3.py -f mem.raw windows.shimcachemem

## Environment-Variables
````
vol2 -f mem.raw envars -p 2464
```

## Open Ports
````
vol2.py -f mem.raw netscan 
```

# Last Exit: Bulk-Extractor

If nothing is working:

```
brew install bulk_extractor
bulk_extractor -V // App-Check

bulk_extractor -o out mem.raw
```