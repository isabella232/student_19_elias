# BLS Cosigning via a Gossip Protocol

This semester project develops and compares alternative implementations of the gossip-based aggregation. The main goal of the new implementations is to reduce the bandwidth used and to be relatively fast. 
Furthermore, this project adds an hybrid implementation of trees and gossiping inside Cothority's ONet library, which is used for a new implementation of signature aggregation.


## Install and run

```
go get github.com/dedis/student_19_elias
```

Make sure that go.mod is pointing to the correct version of ONet. If needed, get the following ONet version (which has HybridRumor) and in go.mod point to the directory where this was cloned:```
go get github.com/dedis/student_19_elias_onet

```

Navigate to `student_19_elias/blscosi_hybrid_rumor/blscosi_hybrid_rumor`.

```
go install
```

## Run a simulation

Navigate to `student_19_elias/blscosi_hybrid_rumor/simulation_bundle/`.

```
go install
simulation_bundle local.toml
```
