// Package store defines the Store interface and its bbolt implementation.
// All state mutations go through Store with monotonic indexes (Raft-FSM-
// compatible, PRD §18). Metrics and logs NEVER touch the Store. Read
// transactions must be bounded/paginated: bbolt is single-writer.
// (PRD §5.2.3, §15.2.)
package store
