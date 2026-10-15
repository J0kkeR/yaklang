package cvequeryops

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yaklang/gorm"

	"github.com/yaklang/yaklang/common/consts"
	"github.com/yaklang/yaklang/common/cve/cveresources"
)

// 回归测试：batchMergeCVEV5Fields 的 SQLite IN (?) 语法修复与批量容错

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(consts.SQLite, ":memory:")
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&cveresources.CVE{}).Error)
	return db
}

// TestBatchMergeCVEV5Fields_QuerySucceeds_BatchPathProven
// 验证批量查询走的是批量路径（而非 fallback），
// 通过检查 batchFallbackUsed 标志确保 IN (?) 语法修复后批量查询成功执行。
// 如果有人将 IN (?) 改回 IN ?，本测试会因为 batchFallbackUsed == true 而失败。
func TestBatchMergeCVEV5Fields_QuerySucceeds_BatchPathProven(t *testing.T) {
	db := setupTestDB(t)

	// 预置两条已有记录
	db.Create(&cveresources.CVE{CVE: "CVE-2024-0001", DescriptionMain: "existing desc"})
	db.Create(&cveresources.CVE{CVE: "CVE-2024-0002", DescriptionMain: "existing desc"})

	v5s := []*cveresources.CVE{
		{CVE: "CVE-2024-0001", Title: "V5 Title 0001", Vendor: "vendor-a"},
		{CVE: "CVE-2024-0002", Title: "V5 Title 0002", Vendor: "vendor-b"},
		{CVE: "CVE-2024-0003", Title: "New from V5"}, // 不存在 → 创建
	}

	batchFallbackUsed = false // 重置观察标志
	err := batchMergeCVEV5Fields(db, v5s)
	require.NoError(t, err)

	// 核心断言：必须走批量路径，不能走 fallback。
	// IN (?) 语法正确 → 批量查询成功 → batchFallbackUsed == false。
	// 如果有人把 IN (?) 改回 IN ? → 语法错误 → batchFallbackUsed == true → 此断言失败。
	assert.False(t, batchFallbackUsed,
		"批量查询应走批量路径而非 fallback。如果此断言失败，说明 IN (?) 语法被破坏（可能被改回 IN ?）")

	// 验证 V5 字段确实落库
	var rec1, rec3 cveresources.CVE
	require.NoError(t, db.Where("cve = ?", "CVE-2024-0001").First(&rec1).Error)
	assert.Equal(t, "V5 Title 0001", rec1.Title, "V5 title 应合并到已有记录")
	assert.Equal(t, "existing desc", rec1.DescriptionMain, "已有 DescriptionMain 应保留")

	require.NoError(t, db.Where("cve = ?", "CVE-2024-0003").First(&rec3).Error)
	assert.Equal(t, "New from V5", rec3.Title, "不存在的记录应被创建")
}

// TestBatchMergeCVEV5Fields_SingleFailureSkipped_Deterministic
// 使用 SQLite trigger + RAISE(ABORT) 构造确定性失败（替代不可靠的超长字符串），
// 验证记录级错误被跳过（不回滚整个事务），其他记录正常处理。
func TestBatchMergeCVEV5Fields_SingleFailureSkipped_Deterministic(t *testing.T) {
	db := setupTestDB(t)

	// 预置记录
	db.Create(&cveresources.CVE{CVE: "CVE-2024-0100", DescriptionMain: "desc"})
	db.Create(&cveresources.CVE{CVE: "CVE-2024-0101", DescriptionMain: "desc"})

	// 创建确定性失败 trigger：针对特定 CVE 的 INSERT 和 UPDATE 都会触发 RAISE(ABORT)
	createFailTriggers(t, db, "CVE-2024-0100")

	v5s := []*cveresources.CVE{
		{CVE: "CVE-2024-0100", Title: "will fail (trigger)"}, // trigger 拦截 → 记录级错误 → 跳过
		{CVE: "CVE-2024-0101", Title: "also good"},             // 不受 trigger 影响 → 成功
		{CVE: "CVE-2024-0102", Title: "new record"},           // 新记录 → 创建成功
	}

	batchFallbackUsed = false
	err := batchMergeCVEV5Fields(db, v5s)
	require.NoError(t, err, "记录级错误（trigger 拦截）不应导致整体报错")
	assert.False(t, batchFallbackUsed, "批量路径应正常工作（trigger 是记录级错误）")

	// 验证未被拦截的记录确实被处理
	var rec2, rec3 cveresources.CVE
	require.NoError(t, db.Where("cve = ?", "CVE-2024-0101").First(&rec2).Error)
	assert.Equal(t, "also good", rec2.Title, "不受 trigger 影响的记录应正常合并")

	require.NoError(t, db.Where("cve = ?", "CVE-2024-0102").First(&rec3).Error)
	assert.Equal(t, "new record", rec3.Title, "新记录应被创建")
}

// TestBatchMergeCVEV5Fields_DatabaseLevelError_Rollback
// 验证数据库级错误（只读数据库）导致回滚并返回错误，而非静默成功。
// 这确保了写入失败不会返回成功（Copilot 第一条意见）。
func TestBatchMergeCVEV5Fields_DatabaseLevelError_Rollback(t *testing.T) {
	db := setupTestDB(t)

	// 预置记录（在数据库变为只读之前）
	db.Create(&cveresources.CVE{CVE: "CVE-2024-0200", DescriptionMain: "seed"})

	// 将数据库设为只读模式（SQLite query_only PRAGMA）
	require.NoError(t, db.Exec("PRAGMA query_only = true").Error,
		"设置只读模式失败")

	v5s := []*cveresources.CVE{
		{CVE: "CVE-2024-0200", Title: "attempt write to readonly"},
		{CVE: "CVE-2024-0201", Title: "another attempt"}, // 新记录创建也应失败
	}

	batchFallbackUsed = false
	err := batchMergeCVEV5Fields(db, v5s)
	// 只读数据库的写入应该导致数据库级错误 → 回滚并返回错误
	require.Error(t, err, "只读数据库的写入不应返回成功")
	assert.Contains(t, err.Error(), "database-level error",
		"错误信息应标明是数据库级错误")
}

// TestBatchMergeCVEV5Fields_EmptyBatch 验证空批量和 nil 输入不报错
func TestBatchMergeCVEV5Fields_EmptyBatch(t *testing.T) {
	db := setupTestDB(t)
	err := batchMergeCVEV5Fields(db, nil)
	assert.NoError(t, err)
	err = batchMergeCVEV5Fields(db, []*cveresources.CVE{})
	assert.NoError(t, err)
}

// TestBatchMergeCVEV5Fields_LargeBatch 验证大批量下 IN (?) 语法正确展开且批量路径正常
func TestBatchMergeCVEV5Fields_LargeBatch(t *testing.T) {
	db := setupTestDB(t)
	var v5s []*cveresources.CVE
	for i := 0; i < 100; i++ {
		cveID := fmt.Sprintf("CVE-2024-%04d", i)
		db.Create(&cveresources.CVE{CVE: cveID, DescriptionMain: "seed"})
		v5s = append(v5s, &cveresources.CVE{CVE: cveID, Title: "batch title"})
	}
	batchFallbackUsed = false
	err := batchMergeCVEV5Fields(db, v5s)
	require.NoError(t, err)
	assert.False(t, batchFallbackUsed, "100 条批量应走批量路径")

	var count int64
	db.Model(&cveresources.CVE{}).Where("title = ?", "batch title").Count(&count)
	assert.Equal(t, int64(100), count, "全部 100 条的 title 都应被合并")
}

// createFailTriggers creates BEFORE INSERT and BEFORE UPDATE triggers that
// deterministically abort for a specific CVE ID using RAISE(ABORT, ...).
func createFailTriggers(t *testing.T, db *gorm.DB, cveID string) {
	t.Helper()

	// Trigger 名称不能包含 '-'，用 '_' 替换
	safeID := strings.ReplaceAll(cveID, "-", "_")

	// BEFORE INSERT trigger
	insertTrigger := fmt.Sprintf(`
		CREATE TRIGGER IF NOT EXISTS fail_insert_%s
		BEFORE INSERT ON cves
		WHEN NEW.cve = '%s'
		BEGIN
			SELECT RAISE(ABORT, 'intentional_test_failure: insert blocked for %s');
		END;
	`, safeID, cveID, cveID)

	// BEFORE UPDATE trigger
	updateTrigger := fmt.Sprintf(`
		CREATE TRIGGER IF NOT EXISTS fail_update_%s
		BEFORE UPDATE ON cves
		WHEN NEW.cve = '%s'
		BEGIN
			SELECT RAISE(ABORT, 'intentional_test_failure: update blocked for %s');
		END;
	`, safeID, cveID, cveID)

	require.NoError(t, db.Exec(insertTrigger).Error,
		"创建 INSERT trigger 失败（表名或语法问题）")
	require.NoError(t, db.Exec(updateTrigger).Error,
		"创建 UPDATE trigger 失败")
}
