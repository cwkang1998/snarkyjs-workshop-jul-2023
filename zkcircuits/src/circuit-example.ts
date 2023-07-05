import {
  Field,
  SelfProof,
  Experimental,
  Struct,
  Poseidon,
  verify,
} from 'snarkyjs';

class CircuitState extends Struct({
  stepValue: Field,
  commitment: Field,
}) {}

const main = async () => {
  console.log("Initializing...")
  const ZKCircuit = Experimental.ZkProgram({
    publicInput: CircuitState,
    publicOutput: Field, // currentStep

    methods: {
      init: {
        privateInputs: [Field],
        method(circuitState: CircuitState, secret: Field) {
          circuitState.stepValue = Field(1);
          circuitState.commitment = Poseidon.hash([secret]);
          return circuitState.stepValue;
        },
      },
      step: {
        privateInputs: [Field, SelfProof],

        method(
          circuitState: CircuitState,
          secret: Field,
          earlierProof: SelfProof<CircuitState, Field>
        ) {
          earlierProof.publicInput.commitment.assertEquals(
            Poseidon.hash([secret])
          );
          earlierProof.verify();
          return earlierProof.publicInput.stepValue.add(circuitState.stepValue);
        },
      },
    },
  });

  console.log("Compiling...");
  const { verificationKey } = await ZKCircuit.compile();

  const firstProof = await ZKCircuit.init(
    { commitment: Poseidon.hash([Field(156561223)]), stepValue: Field(1) },
    Field(156561223)
  );
  console.log(
    `firstProof Verification: ${await verify(firstProof, verificationKey)}`
  );
  console.log(`firstProof stepValue: ${firstProof.publicOutput.toString()}`);

  const subsequentProof = await ZKCircuit.step(
    { commitment: Poseidon.hash([Field(156561223)]), stepValue: Field(5) },
    Field(156561223),
    firstProof
  );
  console.log(
    `subsequentProof Verification: ${await verify(subsequentProof, verificationKey)}`
  );
  console.log(`subsequentProof stepValue: ${subsequentProof.publicOutput.toString()}`);


  // This will fail because the secret is wrong
  const badProof = await ZKCircuit.step(
    { commitment: Poseidon.hash([Field(156561223)]), stepValue: Field(5) },
    Field(101010),
    subsequentProof
  );
  console.log(
    `badProof Verification: ${await verify(badProof, verificationKey)}`
  );
  console.log(`badProof stepValue: ${badProof.publicOutput.toString()}`);
};

main();
