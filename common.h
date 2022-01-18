#ifndef COMMON_H
#define COMMON_H

#define REPEATED_OPERATOR_COMPARISON(Op1, Op2, M, ...)                                                                             \
    (REPEATED_OPERATOR_COMPARISON__(__VA_ARGS__, 8, 7, 6, 5, 4, 3, 2, 1)(Op1, Op2, (M), __VA_ARGS__))
#define REPEATED_OPERATOR_COMPARISON__(_1, _2, _3, _4, _5, _6, _7, _8, X, ...) REPEATED_OPERATOR_COMPARISON_##X
#define REPEATED_OPERATOR_COMPARISON_1(Op1, Op2, M, X) ((X) Op1 M)
#define REPEATED_OPERATOR_COMPARISON_2(Op1, Op2, M, X, ...) ((X) Op1 M) Op2 REPEATED_OPERATOR_COMPARISON_1(Op1, Op2, M, __VA_ARGS__)
#define REPEATED_OPERATOR_COMPARISON_3(Op1, Op2, M, X, ...) ((X) Op1 M) Op2 REPEATED_OPERATOR_COMPARISON_2(Op1, Op2, M, __VA_ARGS__)
#define REPEATED_OPERATOR_COMPARISON_4(Op1, Op2, M, X, ...) ((X) Op1 M) Op2 REPEATED_OPERATOR_COMPARISON_3(Op1, Op2, M, __VA_ARGS__)
#define REPEATED_OPERATOR_COMPARISON_5(Op1, Op2, M, X, ...) ((X) Op1 M) Op2 REPEATED_OPERATOR_COMPARISON_4(Op1, Op2, M, __VA_ARGS__)
#define REPEATED_OPERATOR_COMPARISON_6(Op1, Op2, M, X, ...) ((X) Op1 M) Op2 REPEATED_OPERATOR_COMPARISON_5(Op1, Op2, M, __VA_ARGS__)
#define REPEATED_OPERATOR_COMPARISON_7(Op1, Op2, M, X, ...) ((X) Op1 M) Op2 REPEATED_OPERATOR_COMPARISON_6(Op1, Op2, M, __VA_ARGS__)
#define REPEATED_OPERATOR_COMPARISON_8(Op1, Op2, M, X, ...) ((X) Op1 M) Op2 REPEATED_OPERATOR_COMPARISON_7(Op1, Op2, M, __VA_ARGS__)

#define ANY_EQUAL(M, ...) REPEATED_OPERATOR_COMPARISON(==, ||, M, __VA_ARGS__)
#define ARG_IN_LIST ANY_EQUAL
#define ANY_NOT_EQUAL(M, ...) REPEATED_OPERATOR_COMPARISON(!=, ||, M, __VA_ARGS__)
#define ALL_EQUAL(M, ...) REPEATED_OPERATOR_COMPARISON(==, &&, M, __VA_ARGS__)
#define ALL_NOT_EQUAL(M, ...) REPEATED_OPERATOR_COMPARISON(!=, &&, M, __VA_ARGS__)

#define UNUSED(...) UNUSED_IMPL( VA_NUM_ARGS(__VA_ARGS__))(__VA_ARGS__ )
#define UNUSED_IMPL(nargs) UNUSED_IMPL_(nargs)
#define UNUSED_IMPL_(nargs) UNUSED ## nargs

#define VA_NUM_ARGS(...) VA_NUM_ARGS_IMPL(100, ##__VA_ARGS__, 5, 4, 3, 2, 1, 0 )
#define VA_NUM_ARGS_IMPL(_0,_1,_2,_3,_4,_5, N,...) N
#define UNUSED0()
#define UNUSED1(a)         (void)(a)
#define UNUSED2(a,b)       (void)(a),UNUSED1(b)
#define UNUSED3(a,b,c)     (void)(a),UNUSED2(b,c)
#define UNUSED4(a,b,c,d)   (void)(a),UNUSED3(b,c,d)
#define UNUSED5(a,b,c,d,e) (void)(a),UNUSED4(b,c,d,e)

#endif /* COMMON_H */
