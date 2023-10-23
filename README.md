# bitshred-python
Bitshred python implementation


## Build \(Docker\)

```bash
docker build . -t nino:bitshred
```

## Usage \(Docker\)

```bash
docker run --rm --volume \<input_folder\>:/input:ro --volume \<output_folder\>:/db --entrypoint \<entrypoint\>/src/bitshred nino:bitshred \<options\>
```

- input_folder: folder containing the samples
- output_folder: folder where the results of the tool will be placed in
- entrypoint: version of the tool to run: only supported either `bitshred_single` or `bitshred_single_steps` or `bitshred_openmp`
- options: command line options required by the tool, specified between double quotes. NB: if you have to specify the input folder, you must use `/input` \(any other path is not valid\) and it corresponds to the value specified in `input_folder`. Same reasoning for the output folder, whose path to use is `/db`

Example:
```bash
docker run --rm --volume "/home/nino/samples/":/input:ro --volume "/home/nino/output":/db --entrypoint /bitshred_single/src/bitshred nino:bitshred "-b" "/input/" "-t" "0.60"
```