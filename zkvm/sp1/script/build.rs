use sp1_build::build_program_with_args;

fn main() {
    build_program_with_args("../program", Default::default());
    build_program_with_args("../f-program", Default::default());
}
