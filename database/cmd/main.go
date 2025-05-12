package main

import (
	"flag"

	"zatrano/configs/database_config"
	"zatrano/configs/log_config"
	"zatrano/database"
)

func main() {
	log_config.InitLogger()
	defer log_config.SyncLogger()
	migrateFlag := flag.Bool("migrate", false, "Veritabanı başlatma işlemini çalıştır (migrasyonları içerir)")
	seedFlag := flag.Bool("seed", false, "Veritabanı başlatma işlemini çalıştır (seederları içerir)")
	flag.Parse()

	database_config.InitDB()
	defer database_config.CloseDB()

	db := database_config.GetDB()

	log_config.SLog.Info("Veritabanı başlatma işlemi çalıştırılıyor...")
	database.Initialize(db, *migrateFlag, *seedFlag)

	log_config.SLog.Info("Veritabanı başlatma işlemi tamamlandı.")
}
