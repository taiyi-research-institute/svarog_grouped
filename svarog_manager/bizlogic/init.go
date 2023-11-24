package bizlogic

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-co-op/gocron"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	lbj "gopkg.in/natefinch/lumberjack.v2" // logging
	pb "svarog_manager/proto/gen"
)

const SessionSeconds int64 = 1200

type SessionManager struct {
	pb.UnimplementedMpcSessionManagerServer
	*zap.SugaredLogger
	zap.AtomicLevel

	db *gorm.DB
}

func (srv *SessionManager) InitLogger(log_level, log_dir string) {
	var level zapcore.Level
	switch strings.ToLower(log_level) {
	case "debug", "verb", "verbose":
		level = zap.DebugLevel
	case "info":
		level = zap.InfoLevel
	case "warning", "warn":
		level = zap.WarnLevel
	case "error", "err":
		level = zap.ErrorLevel
	default:
		panic(fmt.Sprintf("unsupported level %s", level))
	}

	srv.AtomicLevel = zap.NewAtomicLevelAt(level)
	w := zapcore.AddSync(&lbj.Logger{
		Filename: fmt.Sprintf("%s/svarog_server.log", log_dir),
		MaxSize:  4, // MB

		// 15 old files and 1 new file. The new file has no suffix.
		MaxBackups: 15,
	})
	w2 := zapcore.NewMultiWriteSyncer(w, zapcore.AddSync(os.Stdout))
	conf_enc := zap.NewDevelopmentEncoderConfig()
	conf_enc.EncodeTime = zapcore.ISO8601TimeEncoder
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(conf_enc),
		w2,
		srv.AtomicLevel,
	)
	// initialize anonymous logger
	srv.SugaredLogger = zap.New(core, zap.WithCaller(true)).Sugar()
}

// create in-memory file db.
func (srv *SessionManager) InitDB() {
	dbpath := "/dev/shm/svarog.db"
	err := os.Remove(dbpath)
	if err != nil && !os.IsNotExist(err) {
		panic(err)
	}

	db, err := gorm.Open(sqlite.Open(dbpath), &gorm.Config{})
	db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		panic(err)
	}
	db.Exec(sql_ddl)
	if err != nil {
		panic(err)
	}
	srv.db = db
}

func (srv *SessionManager) InitSessionRecycler() {
	sch := gocron.NewScheduler(time.UTC)
	sch.Every("1m").Do(func() {
		var err error
		tr := srv.db.Begin()
		now := time.Now().Unix()

		sql := `DELETE FROM mpc_sessions
			WHERE (expire_before_finish < ? AND length(result) = 0)
			OR (expire_after_finish < ? AND length(result) > 0)`
		err = tr.Exec(sql, now, now).Error
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return
		}

		err = tr.Commit().Error
		if err != nil {
			tr.Rollback()
			srv.Error(err)
			return
		}

		srv.Info("Clear expired sessions")
	})
	sch.StartAsync()
}
