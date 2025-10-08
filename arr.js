// console.time("heavy-loop");

let sum = 0;
for (let i = 0; i < 5e7; i++) {  // 2 billion iterations
  sum += i % 10;
}

// console.timeEnd("heavy-loop");
// console.log("Sum:", sum);
