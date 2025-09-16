# Time Consistency Standards

This document outlines the time unit standards and consistency guidelines for the APIShield application.

## Time Unit Standards

### Internal Storage
- **Discovery Manager**: Stores intervals in **minutes**
- **Realtime Monitoring**: Stores intervals in **seconds**
- **Celery Tasks**: Uses **seconds** for scheduling
- **Session Timeout**: Uses **seconds**
- **JWT Security**: Uses **seconds**

### Display Standards
- **User-facing displays**: Use human-readable format (e.g., "1 hour", "30 minutes", "2 days")
- **Form inputs**: Specify units clearly (e.g., "Timeout (minutes)")
- **Configuration**: Use appropriate units for the context

## Template Filters

### `format_interval` Filter
Converts minutes to human-readable format:
```jinja2
{{ discovery_settings.interval|format_interval }}
```
Examples:
- 30 minutes → "30 minutes"
- 60 minutes → "1 hour"
- 120 minutes → "2 hours"
- 1440 minutes → "1 day"

### `format_seconds` Filter
Converts seconds to human-readable format:
```jinja2
{{ timeout_seconds|format_seconds }}
```
Examples:
- 30 seconds → "30 seconds"
- 60 seconds → "1 minute"
- 3600 seconds → "1 hour"
- 86400 seconds → "1 day"

## Fixed Issues

### 1. Discovery Time Display
**Problem**: Services page showed "Runs every 60 hours" instead of "Runs every 1 hour"
**Solution**: 
- Added `format_interval` template filter
- Updated services.html template to use the filter
- Fixed discovery interval options in modal

### 2. Time Unit Inconsistency
**Problem**: Different parts of the application used different time units without clear conversion
**Solution**:
- Established clear standards for internal storage
- Created template filters for consistent display
- Updated templates to use standardized formatting

## Best Practices

1. **Always specify units** in form labels and help text
2. **Use template filters** for time display instead of inline calculations
3. **Store time values** in the most appropriate unit for the context
4. **Convert for display** using the provided template filters
5. **Be consistent** with pluralization (e.g., "1 hour" vs "2 hours")

## Examples

### Good Practices
```html
<!-- Clear unit specification -->
<label for="timeout">Timeout (minutes)</label>

<!-- Using template filters -->
<span>Runs every {{ interval|format_interval }}</span>

<!-- Consistent pluralization -->
<span>{{ duration|format_seconds }}</span>
```

### Avoid
```html
<!-- Unclear units -->
<span>Runs every {{ interval }} hours</span>

<!-- Inline calculations -->
<span>{{ interval / 60 }} hours</span>

<!-- Inconsistent pluralization -->
<span>{{ interval }} hour</span>
```

## Configuration Values

### Discovery Intervals (minutes)
- 30 minutes
- 60 minutes (1 hour)
- 120 minutes (2 hours)
- 360 minutes (6 hours)
- 1440 minutes (1 day)

### Celery Schedules (seconds)
- 3600 seconds (1 hour)
- 21600 seconds (6 hours)
- 86400 seconds (24 hours)
- 604800 seconds (7 days)

### Session Timeout (seconds)
- 3600 seconds (1 hour) - default

### JWT Expiration (seconds)
- 3600 seconds (1 hour) - default
- 86400 seconds (1 day)
- 31536000 seconds (1 year)
