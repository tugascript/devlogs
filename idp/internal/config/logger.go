package config

type LoggerConfig struct {
	isDebug     bool
	env         string
	serviceName string
}

func NewLoggerConfig(isDebug bool, env, serviceName string) LoggerConfig {
	return LoggerConfig{
		isDebug:     isDebug,
		env:         env,
		serviceName: serviceName,
	}
}

func (l *LoggerConfig) IsDebug() bool {
	return l.isDebug
}

func (l *LoggerConfig) Env() string {
	return l.env
}

func (l *LoggerConfig) ServiceName() string {
	return l.serviceName
}
