package utils

import "time"

func ToSecondsDuration(secs int64) time.Duration {
	return time.Duration(secs) * time.Second
}

func ToDaysDuration(days int64) time.Duration {
	return time.Duration(days) * time.Hour * 24
}
