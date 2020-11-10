// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package replstatus

import (
	"context"
	"errors"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type oplogInfo struct {
	allocated int64
	used      float64
	firstTs   int64
	lastTs    int64
	diff      int64
}

// CollSize contains data about collection size
type CollSize struct {
	MaxSize int64   `bson:"maxSize"` // Shows the maximum size of the collection.
	Size    float64 `bson:"size"`    // The total size in memory of all records in a collection.
}

const oplogCol = "oplog.rs"

func getReplicationInfo(mongoSession *mongo.Client) (*oplogInfo, error) {
	// get oplog.rs collection
	db := mongoSession.Database("local")
	if collections, err := db.ListCollectionNames(context.TODO(), bson.M{}); err != nil || !contains(collections, oplogCol) {
		if err == nil {
			err = errors.New("collection oplog.rs was not found")
		}

		return nil, err
	}
	collection := db.Collection(oplogCol)

	// get oplog size
	var oplogSize CollSize
	if err := db.RunCommand(context.TODO(), bson.M{"collStats": "oplog.rs"}).Decode(&oplogSize); err != nil {
		return nil, err
	}

	// get first and last items in the oplog
	firstTs, err := getOpTimestamp(collection, 1)
	if err != nil {
		return nil, err
	}

	lastTs, err := getOpTimestamp(collection, -1)
	if err != nil {
		return nil, err
	}

	diff := lastTs - firstTs

	return &oplogInfo{
		allocated: oplogSize.MaxSize,
		used:      oplogSize.Size,
		firstTs:   firstTs,
		lastTs:    lastTs,
		diff:      diff,
	}, nil
}

func getOpTimestamp(collection *mongo.Collection, sort int) (int64, error) {
	var result struct {
		Timestamp primitive.Timestamp `bson:"ts"` // See: https://docs.mongodb.com/manual/reference/bson-types/#timestamps
	}

	findOptions := options.FindOne().SetSort(bson.M{"$natural": sort})
	err := collection.FindOne(context.TODO(), bson.M{}, findOptions).Decode(&result)
	return int64(result.Timestamp.T), err
}

func contains(s []string, x string) bool {
	for _, n := range s {
		if x == n {
			return true
		}
	}
	return false
}
