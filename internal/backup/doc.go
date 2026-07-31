// Package backup implements S3 state replication and backup/restore:
// Store-level CDC (bbolt has NO WAL — change records on the monotonic index),
// periodic snapshots, client-side encryption with the escrowed master key
// (key ceremony at init), restore with the documented recovery order.
// (PRD §15.3.)
package backup
